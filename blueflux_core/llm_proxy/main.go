package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// LogEntry matches the BlueFlux Telemetry format with enhanced correlation
type LogEntry struct {
	Timestamp    float64                `json:"timestamp"`      // Unix timestamp for programmatic use
	TimestampISO string                 `json:"timestamp_iso"`  // Human-readable ISO 8601 format
	SessionID    string                 `json:"session_id"`
	Type         string                 `json:"type"`           // "request", "response", "error"
	Content      string                 `json:"content"`
	SourceIP     string                 `json:"source_ip,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Method       string                 `json:"method,omitempty"`
	Path         string                 `json:"path,omitempty"`
	Status       int                    `json:"status,omitempty"`
	Duration     float64                `json:"duration_ms,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Log File Path (Shared Volume)
// Maps to host path: infra/data/llm_logs/proxy.jsonl (because ./data:/data in docker-compose.yml)
const LogFile = "/data/llm_logs/proxy.jsonl"

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func appendLog(entry LogEntry) {
	// Ensure timestamp_iso is set if not already
	if entry.TimestampISO == "" && entry.Timestamp > 0 {
		entry.TimestampISO = time.Unix(int64(entry.Timestamp), 0).UTC().Format(time.RFC3339)
	}

	// Ensure log directory exists
	if err := os.MkdirAll("/data/llm_logs", 0755); err != nil {
		log.Printf("[ERROR] Failed to create log directory /data/llm_logs: %v", err)
		return
	}

	f, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file %s: %v", LogFile, err)
		return
	}
	defer f.Close()

	bytes, _ := json.Marshal(entry)
	if _, err := f.WriteString(string(bytes) + "\n"); err != nil {
		log.Printf("[ERROR] Failed to write to log file %s: %v", LogFile, err)
		return
	}

	snippet := entry.Content
	if len(snippet) > 100 {
		snippet = snippet[:100]
	}
	log.Printf("[TELEMETRY] %s [%s]: %s", entry.Type, entry.TimestampISO, snippet)
}

// ======================= PROMPT EXTRACTION =======================

// extractPromptFromJSON handles application/json bodies:
// - If body has {"message": "..."} → AI prompt
// - Otherwise it's considered generic API traffic.
func extractPromptFromJSON(body []byte) (string, bool, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", false, fmt.Errorf("failed to parse JSON body: %v", err)
	}

	// Meta-style JSON could have other shapes, but for our own tests we use "message"
	if msg, ok := obj["message"].(string); ok && msg != "" {
		return msg, true, nil
	}

	// No "message" → not an AI prompt, just normal API/app traffic
	return "", false, nil
}

// extractPromptFromForm parses form-encoded request and extracts the prompt
// Handles both GraphQL format (from real malware) and simple form format (from fallback)
func extractPromptFromForm(body []byte) (string, bool, bool, error) {
	// returns: (prompt, isPromptRequest, isAuthTOS, error)
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false, false, fmt.Errorf("failed to parse form data: %v", err)
	}

	// Detect explicit Meta auth/TOS
	reqName := values.Get("fb_api_req_friendly_name")
	if reqName == "useAbraAcceptTOSForTempUserMutation" {
		// Auth/TOS request, not a normal prompt
		return "", false, true, nil
	}

	// Simple form: message=...
	if message := values.Get("message"); message != "" {
		decoded, err := url.QueryUnescape(message)
		if err == nil && len(decoded) > 0 {
			return decoded, true, false, nil
		}
		return message, true, false, nil
	}

	// GraphQL-style: variables={"message":{"sensitive_string_value":"..."}}
	variablesStr := values.Get("variables")
	if variablesStr == "" {
		return "", false, false, fmt.Errorf("no 'variables' or 'message' field in form data")
	}

	decodedVars, err := url.QueryUnescape(variablesStr)
	if err != nil {
		decodedVars = variablesStr
	}

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(decodedVars), &variables); err != nil {
		return "", false, false, fmt.Errorf("failed to parse variables JSON: %v", err)
	}

	message, ok := variables["message"].(map[string]interface{})
	if !ok {
		// Not a prompt, some other GraphQL operation
		return "", false, false, nil
	}

	prompt, ok := message["sensitive_string_value"].(string)
	if !ok {
		return "", false, false, fmt.Errorf("no 'sensitive_string_value' in message")
	}

	return prompt, true, false, nil
}

// extractPrompt is the unified entry point:
// - If Content-Type is JSON → use extractPromptFromJSON
// - If form-encoded → use extractPromptFromForm
func extractPrompt(r *http.Request, body []byte) (prompt string, isPrompt bool, isAuthTOS bool, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		prompt, isPrompt, err = extractPromptFromJSON(body)
		return prompt, isPrompt, false, err
	}

	// Default: treat as form-encoded (Meta)
	prompt, isPrompt, isAuthTOS, err = extractPromptFromForm(body)
	return prompt, isPrompt, isAuthTOS, err
}

// ======================= OPENROUTER FORWARDING =======================

// forwardToOpenRouter forwards the request to OpenRouter API and returns the FULL response
// Returns both the extracted message and the raw response for complete logging
func forwardToOpenRouter(prompt string, stream bool) (map[string]interface{}, string, error) {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	apiURL := os.Getenv("OPENROUTER_API_URL")
	model := os.Getenv("OPENROUTER_MODEL")

	if apiURL == "" {
		apiURL = "https://openrouter.ai/api/v1/chat/completions"
	}
	if model == "" {
		model = "openai/gpt-4o-mini"
	}
	if apiKey == "" {
		return nil, "", fmt.Errorf("OPENROUTER_API_KEY environment variable not set")
	}

	payload := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 2000,
	}
	if stream {
		payload["stream"] = true
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal error: %v", err)
	}

	log.Printf("[PROXY] Forwarding AI prompt to OpenRouter (model=%s)", model)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "http://localhost")
	req.Header.Set("X-Title", "BlueFlux Proxy")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("OpenRouter HTTP error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading OpenRouter body: %v", err)
	}
	rawResponse := string(bodyBytes)

	log.Printf("[PROXY] OpenRouter response (status=%d, size=%d bytes)", resp.StatusCode, len(rawResponse))

	if resp.StatusCode != http.StatusOK {
		return nil, rawResponse, fmt.Errorf("OpenRouter returned status %d", resp.StatusCode)
	}

	var openResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &openResp); err != nil {
		return nil, rawResponse, fmt.Errorf("failed to parse OpenRouter JSON: %v", err)
	}

	msg := ""
	if choices, ok := openResp["choices"].([]interface{}); ok && len(choices) > 0 {
		if ch, ok := choices[0].(map[string]interface{}); ok {
			if m, ok := ch["message"].(map[string]interface{}); ok {
				if c, ok := m["content"].(string); ok {
					msg = c
				}
			}
		}
	}
	if msg == "" {
		msg = rawResponse
	}

	result := map[string]interface{}{
		"message":      msg,
		"raw_response": openResp,
		"model_used":   model,
		"raw_json":     rawResponse,
	}
	return result, rawResponse, nil
}

// ======================= GENERIC UPSTREAM FORWARDING =======================

// forwardToUpstream forwards non-AI traffic to an upstream service if configured.
// If UPSTREAM_URL is not set, it returns a simple stub JSON.
func forwardToUpstream(r *http.Request, body []byte) ([]byte, int, error) {
	upstream := os.Getenv("UPSTREAM_URL")
	if upstream == "" {
		// Stub response: useful for testing without a real backend
		stub := map[string]interface{}{
			"status": "ok",
			"note":   "no UPSTREAM_URL configured, stub response from proxy",
		}
		respBytes, _ := json.Marshal(stub)
		return respBytes, http.StatusOK, nil
	}

	targetURL := upstream
	if !strings.HasPrefix(upstream, "http") {
		targetURL = "http://" + upstream
	}
	targetURL = strings.TrimRight(targetURL, "/") + r.URL.Path

	req, err := http.NewRequest(r.Method, targetURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to create upstream request: %v", err)
	}

	// Copy headers except Host
	for k, v := range r.Header {
		if strings.ToLower(k) == "host" {
			continue
		}
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("upstream HTTP error: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed reading upstream body: %v", err)
	}

	return respBytes, resp.StatusCode, nil
}

// ======================= MAIN PROXY HANDLER =======================

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	// Session ID: IP + timestamp
	sessionID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())

	log.Printf("[PROXY] Incoming request from %s to %s %s", clientIP, r.Method, r.URL.Path)

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	now := time.Now()
	appendLog(LogEntry{
		Timestamp:    float64(now.Unix()),
		TimestampISO: now.UTC().Format(time.RFC3339),
		SessionID:    sessionID,
		Type:         "request",
		Content:      string(body),
		SourceIP:     clientIP,
		UserAgent:    r.Header.Get("User-Agent"),
		Method:       r.Method,
		Path:         r.URL.Path,
		Metadata: map[string]interface{}{
			"content_length": len(body),
			"headers":        r.Header,
		},
	})

	// Health-path shortcut (for safety, though you already have /health)
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// Extract prompt / classify request
	prompt, isPromptRequest, isAuthTOS, err := extractPrompt(r, body)
	if err != nil {
		log.Printf("[WARN] Prompt extraction error: %v", err)
		log.Printf("[DEBUG] Request body: %s", string(body))
	}

	// Auth/TOS (Meta-style)
	if isAuthTOS {
		log.Printf("[PROXY] Auth/TOS request detected, returning mock success")
		authResponse := map[string]interface{}{
			"data": map[string]interface{}{
				"xab_abra_accept_terms_of_service": map[string]interface{}{
					"new_temp_user_auth": map[string]interface{}{
						"access_token": "mock_token_for_demo",
					},
				},
			},
		}
		respBytes, _ := json.Marshal(authResponse)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)

		now = time.Now()
		appendLog(LogEntry{
			Timestamp:    float64(now.Unix()),
			TimestampISO: now.UTC().Format(time.RFC3339),
			SessionID:    sessionID,
			Type:         "response",
			Content:      string(respBytes),
			SourceIP:     clientIP,
			Status:       http.StatusOK,
			Duration:     float64(time.Since(startTime).Milliseconds()),
			Metadata: map[string]interface{}{
				"request_type": "auth_tos",
			},
		})
		return
	}

	// AI prompt path
	if isPromptRequest && prompt != "" {
		log.Printf("[PROXY] Extracted AI prompt (length: %d): %s", len(prompt), prompt)

		stream := r.URL.Query().Get("stream") == "true" ||
			strings.Contains(r.Header.Get("Accept"), "text/event-stream")

		metaResp, rawMetaResponse, err := forwardToOpenRouter(prompt, stream)
		if err != nil {
			log.Printf("[ERROR] OpenRouter API forwarding failed: %v", err)

			appendLog(LogEntry{
				Timestamp:    float64(time.Now().Unix()),
				TimestampISO: time.Now().UTC().Format(time.RFC3339),
				SessionID:    sessionID,
				Type:         "error",
				Content:      fmt.Sprintf("OpenRouter API call failed: %v", err),
				SourceIP:     clientIP,
				Status:       http.StatusBadGateway,
				Metadata: map[string]interface{}{
					"error_type": "openrouter_forwarding_failed",
					"prompt":     prompt,
					"raw_error":  rawMetaResponse,
				},
			})

			errorResp := map[string]interface{}{
				"errors": []map[string]interface{}{
					{"message": fmt.Sprintf("Proxy error: %v", err)},
				},
			}
			respBytes, _ := json.Marshal(errorResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write(respBytes)

			appendLog(LogEntry{
				Timestamp:    float64(time.Now().Unix()),
				TimestampISO: time.Now().UTC().Format(time.RFC3339),
				SessionID:    sessionID,
				Type:         "response",
				Content:      string(respBytes),
				SourceIP:     clientIP,
				Status:       http.StatusBadGateway,
				Duration:     float64(time.Since(startTime).Milliseconds()),
				Metadata: map[string]interface{}{
					"error": true,
				},
			})
			return
		}

		log.Printf("[PROXY] Meta AI returned full response (length: %d bytes)", len(rawMetaResponse))
		log.Printf("[PROXY] Full Meta AI response: %s", rawMetaResponse)

		// Wrap into GraphQL-like structure expected by malware
		var graphQLResp map[string]interface{}
		if message, ok := metaResp["message"].(string); ok {
			graphQLResp = map[string]interface{}{
				"data": map[string]interface{}{
					"node": map[string]interface{}{
						"bot_response_message": map[string]interface{}{
							"id":              fmt.Sprintf("%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000),
							"streaming_state": "OVERALL_DONE",
							"composed_text": map[string]interface{}{
								"content": []map[string]interface{}{
									{"text": message},
								},
							},
							"fetch_id": "",
						},
					},
				},
			}
		} else {
			graphQLResp = map[string]interface{}{
				"data": map[string]interface{}{
					"node": map[string]interface{}{
						"bot_response_message": map[string]interface{}{
							"id":              fmt.Sprintf("%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000),
							"streaming_state": "OVERALL_DONE",
							"composed_text": map[string]interface{}{
								"content": []map[string]interface{}{
									{"text": rawMetaResponse},
								},
							},
							"fetch_id": "",
						},
					},
				},
			}
		}

		duration := time.Since(startTime)
		respBytes, _ := json.Marshal(graphQLResp)
		now = time.Now()

		appendLog(LogEntry{
			Timestamp:    float64(now.Unix()),
			TimestampISO: now.UTC().Format(time.RFC3339),
			SessionID:    sessionID,
			Type:         "response",
			Content:      string(respBytes),
			SourceIP:     clientIP,
			Status:       http.StatusOK,
			Duration:     float64(duration.Milliseconds()),
			Metadata: map[string]interface{}{
				"response_size":       len(respBytes),
				"prompt_length":       len(prompt),
				"openrouter_raw":      rawMetaResponse,
				"openrouter_response": metaResp,
			},
		})

		log.Printf("[PROXY] Request completed in %v, response size: %d bytes", duration, len(respBytes))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
		w.Write([]byte("\n"))
		return
	}

	// Non-AI traffic: either generic JSON or some app chatter
	respBytes, status, err := forwardToUpstream(r, body)
	if err != nil {
		log.Printf("[ERROR] Upstream forwarding failed: %v", err)

		appendLog(LogEntry{
			Timestamp:    float64(time.Now().Unix()),
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			SessionID:    sessionID,
			Type:         "error",
			Content:      fmt.Sprintf("Upstream forwarding failed: %v", err),
			SourceIP:     clientIP,
			Status:       http.StatusBadGateway,
			Metadata: map[string]interface{}{
				"error_type": "upstream_forwarding_failed",
			},
		})

		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}

	duration := time.Since(startTime)
	now = time.Now()
	appendLog(LogEntry{
		Timestamp:    float64(now.Unix()),
		TimestampISO: now.UTC().Format(time.RFC3339),
		SessionID:    sessionID,
		Type:         "response",
		Content:      string(respBytes),
		SourceIP:     clientIP,
		Status:       status,
		Duration:     float64(duration.Milliseconds()),
		Metadata: map[string]interface{}{
			"request_type": "generic",
			"response_size": len(respBytes),
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(respBytes)
}

// ======================= MAIN =======================

func main() {
	// Ensure log directory exists at startup
	if err := os.MkdirAll("/data/llm_logs", 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create log directory /data/llm_logs: %v", err)
	}

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Main proxy endpoint
	http.HandleFunc("/v1/proxy", proxyHandler)

	// Catch-all for GraphQL-like endpoints
	http.HandleFunc("/graphql", proxyHandler)
	http.HandleFunc("/api/graphql/", proxyHandler)
	http.HandleFunc("/", proxyHandler)

	log.Println("[PROXY] BlueFlux LLM Proxy starting on :8080")
	log.Println("[PROXY] Listening for malware and app API calls...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
