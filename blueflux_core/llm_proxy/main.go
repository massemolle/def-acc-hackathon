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

// LogEntry matches the BlueFlux Telemetry format
type LogEntry struct {
	Timestamp float64 `json:"timestamp"`
	SessionID string  `json:"session_id"`
	Type      string  `json:"type"` // "request" or "response"
	Content   string  `json:"content"`
}

// Log File Path (Shared Volume)
const LogFile = "/data/llm_logs/proxy.jsonl"

func appendLog(entry LogEntry) {
	f, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	bytes, _ := json.Marshal(entry)
	f.WriteString(string(bytes) + "\n")
	log.Printf("[TELEMETRY] %s: %s", entry.Type, entry.Content)
}

// extractPromptFromForm parses form-encoded GraphQL request and extracts the prompt
func extractPromptFromForm(body []byte) (string, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", fmt.Errorf("failed to parse form data: %v", err)
	}

	variablesStr := values.Get("variables")
	if variablesStr == "" {
		return "", fmt.Errorf("no 'variables' field in form data")
	}

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(variablesStr), &variables); err != nil {
		return "", fmt.Errorf("failed to parse variables JSON: %v", err)
	}

	message, ok := variables["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no 'message' field in variables")
	}

	prompt, ok := message["sensitive_string_value"].(string)
	if !ok {
		return "", fmt.Errorf("no 'sensitive_string_value' in message")
	}

	return prompt, nil
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

	// 2. Log the incoming request
	appendLog(LogEntry{
		Timestamp: float64(time.Now().Unix()),
		SessionID: clientIP,
		Type:      "request",
		Content:   string(body),
	})

	// 3. Parse form data to extract prompt
	prompt, err := extractPromptFromForm(body)
	if err != nil {
		log.Printf("[WARN] Failed to extract prompt from request: %v", err)
		log.Printf("[DEBUG] Request body: %s", string(body))
		
		// Fallback: try to find prompt in raw body as text
		if strings.Contains(string(body), "sensitive_string_value") {
			// Try regex-like extraction as fallback
			parts := strings.Split(string(body), "sensitive_string_value")
			if len(parts) > 1 {
				// Very basic extraction - not robust but works for demo
				remaining := parts[1]
				if idx := strings.Index(remaining, "="); idx != -1 {
					prompt = strings.TrimSpace(remaining[idx+1:])
					if len(prompt) > 200 {
						prompt = prompt[:200] + "..."
					}
				}
			}
		}
		
		if prompt == "" {
			prompt = "Generate a reverse shell script" // Fallback for demo
			log.Printf("[INFO] Using fallback prompt: %s", prompt)
		}
	}

	log.Printf("[PROXY] Extracted prompt (length: %d): %s", len(prompt), prompt)

	// 4. Forward to Meta AI
	stream := r.URL.Query().Get("stream") == "true" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	metaResp, err := forwardToMetaAI(prompt, stream)
	if err != nil {
		log.Printf("[ERROR] Meta AI forwarding failed: %v", err)
		
		// Return error response in GraphQL format malware expects
		errorResp := map[string]interface{}{
			"errors": []map[string]interface{}{
				{
					"message": fmt.Sprintf("Proxy error: %v", err),
				},
			},
		}
		respBytes, _ := json.Marshal(errorResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(respBytes)
		
		appendLog(LogEntry{
			Timestamp: float64(time.Now().Unix()),
			SessionID: clientIP,
			Type:      "response",
			Content:   string(respBytes),
		})
		return
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

	// 6. Log the response
	respBytes, _ := json.Marshal(graphQLResp)
	appendLog(LogEntry{
		Timestamp: float64(time.Now().Unix()),
		SessionID: clientIP,
		Type:      "response",
		Content:   string(respBytes),
	})

	// 7. Send response back to malware in format it expects (newline-separated for streaming compatibility)
	duration := time.Since(startTime)
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