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

// forwardToOpenRouter forwards the request to OpenRouter API and returns the FULL response
// Returns both the extracted message and the raw response for complete logging
// Includes retry logic for rate limits (429 errors)
func forwardToOpenRouter(prompt string, stream bool) (map[string]interface{}, string, error) {
	// Get API configuration from environment
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	apiURL := os.Getenv("OPENROUTER_API_URL")
	model := os.Getenv("OPENROUTER_MODEL")
	
	// Defaults if not set
	if apiURL == "" {
		apiURL = "https://openrouter.ai/api/v1/chat/completions"
	}
	if model == "" {
		model = "meta-llama/llama-3.2-3b-instruct:free"
	}
	
	if apiKey == "" {
		return nil, "", fmt.Errorf("OPENROUTER_API_KEY environment variable not set")
	}
	
	// Fallback models if primary is rate-limited
	fallbackModels := []string{
		"google/gemma-2-2b-it:free",
		"microsoft/phi-3-mini-128k-instruct:free",
		"qwen/qwen-2.5-7b-instruct:free",
	}
	
	modelsToTry := append([]string{model}, fallbackModels...)
	
	var lastErr error
	var lastRawResponse string
	
	// Try primary model first, then fallbacks
	for attempt, tryModel := range modelsToTry {
		if attempt > 0 {
			log.Printf("[PROXY] Retrying with fallback model: %s (attempt %d/%d)", tryModel, attempt+1, len(modelsToTry))
			time.Sleep(time.Duration(attempt) * time.Second) // Exponential backoff
		} else {
			log.Printf("[PROXY] Calling OpenRouter API (model: %s, prompt length: %d)...", tryModel, len(prompt))
		}
		
		// Prepare the request payload with current model
		payload := map[string]interface{}{
			"model": tryModel,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
			"max_tokens": 2000, // Allow longer responses for code generation
		}
		
		if stream {
			payload["stream"] = true
		}
		
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			lastErr = fmt.Errorf("failed to marshal request payload: %v", err)
			continue
		}
		
		// Create HTTP request
		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %v", err)
			continue
		}
		
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("HTTP-Referer", "https://blueflux-proxy")
		req.Header.Set("X-Title", "BlueFlux Proxy")
		
		// Send request
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] OpenRouter HTTP request failed: %v", err)
			lastErr = fmt.Errorf("OpenRouter API request failed: %v", err)
			continue
		}
		
		// Read response
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %v", err)
			continue
		}
		
		rawResponse := string(bodyBytes)
		log.Printf("[PROXY] OpenRouter response received (status: %d, size: %d bytes, model: %s)", resp.StatusCode, len(rawResponse), tryModel)
		
		// Handle rate limiting (429) - retry with next model
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
			log.Printf("[WARN] Rate limited (429) on model %s, trying fallback...", tryModel)
			lastErr = fmt.Errorf("rate limited on model %s", tryModel)
			lastRawResponse = rawResponse
			continue // Try next model
		}
		
		// Handle other errors
		if resp.StatusCode != http.StatusOK {
			log.Printf("[ERROR] OpenRouter API returned error status %d: %s", resp.StatusCode, rawResponse)
			lastErr = fmt.Errorf("OpenRouter API error (status %d): %s", resp.StatusCode, rawResponse)
			lastRawResponse = rawResponse
			continue // Try next model
		}
		
		// Success! Parse response
		var openRouterResp map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &openRouterResp); err != nil {
			log.Printf("[ERROR] Failed to parse OpenRouter response: %v", err)
			lastErr = fmt.Errorf("failed to parse OpenRouter response: %v", err)
			lastRawResponse = rawResponse
			continue // Try next model
		}
		
		// Extract the message content from OpenRouter response format
		// OpenRouter format: {"choices": [{"message": {"content": "..."}}]}
		var messageContent string
		if choices, ok := openRouterResp["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						messageContent = content
					}
				}
			}
		}
		
		if messageContent == "" {
			log.Printf("[WARN] No message content found in OpenRouter response")
			messageContent = rawResponse // Fallback to raw response
		}
		
		log.Printf("[PROXY] OpenRouter response extracted (message length: %d, model: %s)", len(messageContent), tryModel)
		if len(messageContent) > 500 {
			log.Printf("[PROXY] OpenRouter response preview (first 500 chars): %s...", messageContent[:500])
		} else {
			log.Printf("[PROXY] OpenRouter full response: %s", messageContent)
		}
		
		// Return in format compatible with existing code
		result := map[string]interface{}{
			"message":      messageContent,
			"raw_response": openRouterResp, // Include full OpenRouter response
			"model_used":   tryModel,      // Track which model worked
		}
		
		return result, rawResponse, nil
	}
	
	// All models failed
	log.Printf("[ERROR] All models failed. Last error: %v", lastErr)
	return nil, lastRawResponse, fmt.Errorf("all models failed, last error: %v", lastErr)
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
	now := time.Now() // Declare once at function scope
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
		
		now = time.Now() // Reuse the variable declared at function scope
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

	// 4. Forward to OpenRouter API and get FULL response
	stream := r.URL.Query().Get("stream") == "true" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	metaResp, rawMetaResponse, err := forwardToOpenRouter(prompt, stream)
	if err != nil {
		log.Printf("[ERROR] OpenRouter API forwarding failed: %v", err)
		log.Printf("[ERROR] Full error details: %+v", err)
		
		// Log the failure for analysis
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
				"prompt":      prompt,
				"raw_error":   rawMetaResponse, // Include raw error response if available
			},
		})
		
		// Return error response in GraphQL format
		errorResp := map[string]interface{}{
			"errors": []map[string]interface{}{
				{
					"message": fmt.Sprintf("Proxy error: %v", err),
				},
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

	// Log the FULL Meta AI response before processing
	log.Printf("[PROXY] Meta AI returned full response (length: %d bytes)", len(rawMetaResponse))
	log.Printf("[PROXY] Full Meta AI response: %s", rawMetaResponse)

	// 5. Convert Meta AI response to GraphQL format that malware expects
	// The malware's extractLastResponse expects: {"data": {"node": {"bot_response_message": {...}}}}
	// Use the actual response structure from Meta AI if available
	var graphQLResp map[string]interface{}
	
	// Try to preserve the original Meta AI response structure
	if message, ok := metaResp["message"].(string); ok {
		// Build GraphQL response format
		graphQLResp = map[string]interface{}{
			"data": map[string]interface{}{
				"node": map[string]interface{}{
					"bot_response_message": map[string]interface{}{
						"id":              fmt.Sprintf("%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000),
						"streaming_state": "OVERALL_DONE",
						"composed_text": map[string]interface{}{
							"content": []map[string]interface{}{
								{
									"text": message, // FULL message from Meta AI
								},
							},
						},
						"fetch_id": "",
					},
				},
			},
		}
	} else {
		// Fallback if structure is different
		graphQLResp = map[string]interface{}{
			"data": map[string]interface{}{
				"node": map[string]interface{}{
					"bot_response_message": map[string]interface{}{
						"id":              fmt.Sprintf("%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000),
						"streaming_state": "OVERALL_DONE",
						"composed_text": map[string]interface{}{
							"content": []map[string]interface{}{
								{
									"text": rawMetaResponse, // Use raw response if structure parsing fails
								},
							},
						},
						"fetch_id": "",
					},
				},
			},
		}
	}

	// 6. Log the FULL response with correlation (both Meta AI raw response and formatted response)
	duration := time.Since(startTime)
	respBytes, _ := json.Marshal(graphQLResp)
	now = time.Now()
	
	// Log the formatted response (what we send to malware)
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
			"response_size":      len(respBytes),
			"prompt_length":     len(prompt),
			"openrouter_raw":    rawMetaResponse, // FULL OpenRouter response
			"openrouter_response": metaResp,      // Parsed OpenRouter response
		},
	})
	
	log.Printf("[PROXY] Response logged - OpenRouter raw response: %s", rawMetaResponse)

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