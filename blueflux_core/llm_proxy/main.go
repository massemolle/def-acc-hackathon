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

	"llm_proxy/api"
)

// LogEntry matches the BlueFlux Telemetry format with enhanced correlation
type LogEntry struct {
	Timestamp      float64                `json:"timestamp"`       // Unix timestamp for programmatic use
	TimestampISO   string                 `json:"timestamp_iso"`  // Human-readable ISO 8601 format
	SessionID      string                 `json:"session_id"`
	Type           string                 `json:"type"` // "request" or "response"
	Content        string                 `json:"content"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	Method         string                 `json:"method,omitempty"`
	Path           string                 `json:"path,omitempty"`
	Status         int                    `json:"status,omitempty"`
	Duration       float64                `json:"duration_ms,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Log File Path (Shared Volume)
const LogFile = "/data/llm_logs/proxy.jsonl"

func appendLog(entry LogEntry) {
	// Ensure timestamp_iso is set if not already
	if entry.TimestampISO == "" && entry.Timestamp > 0 {
		entry.TimestampISO = time.Unix(int64(entry.Timestamp), 0).UTC().Format(time.RFC3339)
	}
	
	f, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	bytes, _ := json.Marshal(entry)
	f.WriteString(string(bytes) + "\n")
	log.Printf("[TELEMETRY] %s [%s]: %s", entry.Type, entry.TimestampISO, entry.Content[:min(100, len(entry.Content))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractPromptFromForm parses form-encoded request and extracts the prompt
// Handles both GraphQL format (from real malware) and simple form format (from fallback)
func extractPromptFromForm(body []byte) (string, bool, error) {
	// isPromptRequest indicates if this is an actual prompt request (not auth/TOS)
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false, fmt.Errorf("failed to parse form data: %v", err)
	}

	// Check if this is an auth/TOS request (not a prompt)
	reqName := values.Get("fb_api_req_friendly_name")
	if reqName == "useAbraAcceptTOSForTempUserMutation" {
		// This is an auth request, not a prompt - return empty but indicate it's not a prompt
		return "", false, nil
	}

	// Try simple form format first (fallback sends: message=...)
	if message := values.Get("message"); message != "" {
		decoded, err := url.QueryUnescape(message)
		if err == nil && len(decoded) > 0 {
			return decoded, true, nil
		}
	}

	// Try GraphQL format (real malware sends: variables={"message":{"sensitive_string_value":"..."}})
	variablesStr := values.Get("variables")
	if variablesStr == "" {
		return "", false, fmt.Errorf("no 'variables' or 'message' field in form data")
	}

	// URL decode the variables JSON
	decodedVars, err := url.QueryUnescape(variablesStr)
	if err != nil {
		decodedVars = variablesStr // Fallback to original if decode fails
	}

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(decodedVars), &variables); err != nil {
		return "", false, fmt.Errorf("failed to parse variables JSON: %v", err)
	}

	// Check if this is a prompt request (has message field)
	message, ok := variables["message"].(map[string]interface{})
	if !ok {
		// Not a prompt request (might be auth or other GraphQL operation)
		return "", false, nil
	}

	prompt, ok := message["sensitive_string_value"].(string)
	if !ok {
		return "", false, fmt.Errorf("no 'sensitive_string_value' in message")
	}

	return prompt, true, nil
}

// forwardToMetaAI forwards the request to Meta AI and returns the response
func forwardToMetaAI(prompt string, stream bool) (map[string]interface{}, error) {
	meta, err := api.NewMetaAI("", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Meta AI client: %v", err)
	}

	resp, err := meta.Prompt(prompt, stream, 0, true)
	if err != nil {
		return nil, fmt.Errorf("Meta AI API call failed: %v", err)
	}

	return resp, nil
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}
	
	// Generate session ID from client IP + timestamp for correlation
	sessionID := fmt.Sprintf("%s-%d", clientIP, time.Now().Unix())

	log.Printf("[PROXY] Incoming request from %s to %s %s", clientIP, r.Method, r.URL.Path)

	// 1. Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// 2. Log the incoming request with enhanced metadata
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

	// 3. Parse form data to extract prompt and detect request type
	prompt, isPromptRequest, err := extractPromptFromForm(body)
	if err != nil {
		log.Printf("[WARN] Failed to extract prompt from request: %v", err)
		log.Printf("[DEBUG] Request body: %s", string(body))
	}

	// Handle auth/TOS requests - return mock success without calling Meta AI
	if !isPromptRequest {
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
		
		now := time.Now()
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

	// If no prompt extracted, use fallback
	if prompt == "" {
		prompt = "Generate a reverse shell script"
		log.Printf("[INFO] Using fallback prompt: %s", prompt)
	}

	log.Printf("[PROXY] Extracted prompt (length: %d): %s", len(prompt), prompt)

	// 4. Forward to Meta AI (or return mock response for demo)
	stream := r.URL.Query().Get("stream") == "true" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	metaResp, err := forwardToMetaAI(prompt, stream)
	if err != nil {
		log.Printf("[WARN] Meta AI forwarding failed (expected in demo): %v", err)
		log.Printf("[INFO] Returning mock response for demo purposes")
		
		// Return mock response that looks like real Meta AI response
		// This allows the demo to work without real Meta AI credentials
		metaResp = map[string]interface{}{
			"message": fmt.Sprintf("CODE\n# Generated code for: %s\nprint('This is a simulated response for demo')\nCODE", prompt[:50]),
		}
	}

	// 5. Convert Meta AI response to GraphQL format that malware expects
	// The malware's extractLastResponse expects: {"data": {"node": {"bot_response_message": {...}}}}
	graphQLResp := map[string]interface{}{
		"data": map[string]interface{}{
			"node": map[string]interface{}{
				"bot_response_message": map[string]interface{}{
					"id":              fmt.Sprintf("%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000),
					"streaming_state": "OVERALL_DONE",
					"composed_text": map[string]interface{}{
						"content": []map[string]interface{}{
							{
								"text": metaResp["message"],
							},
						},
					},
					"fetch_id": "",
				},
			},
		},
	}

	// 6. Log the response with correlation
	duration := time.Since(startTime)
	respBytes, _ := json.Marshal(graphQLResp)
	now := time.Now()
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
			"response_size": len(respBytes),
			"prompt_length": len(prompt),
		},
	})

	// 7. Send response back to malware in format it expects (newline-separated for streaming compatibility)
	log.Printf("[PROXY] Request completed in %v, response size: %d bytes", duration, len(respBytes))
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Return as newline-separated JSON (malware expects this format for parsing)
	w.Write(respBytes)
	w.Write([]byte("\n")) // Add newline for streaming format compatibility
}

func main() {
	// Ensure log directory exists
	if err := os.MkdirAll("/data/llm_logs", 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create log directory: %v", err)
	}

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Main proxy endpoint
	http.HandleFunc("/v1/proxy", proxyHandler)
	
	// Catch-all for GraphQL endpoints (malware may hit /graphql or /api/graphql/)
	http.HandleFunc("/", proxyHandler)
	http.HandleFunc("/graphql", proxyHandler)
	http.HandleFunc("/api/graphql/", proxyHandler)

	log.Println("[PROXY] BlueFlux LLM Proxy starting on :8080")
	log.Println("[PROXY] Listening for malware API calls...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}