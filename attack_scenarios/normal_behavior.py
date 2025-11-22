"""
Normal behavior simulator - generates benign LLM prompts and logs them.

This script simulates legitimate user interactions with an LLM service,
creating normal traffic patterns that can be used as a baseline for
detecting malicious prompt injection attempts.
"""

import time
import random
import requests
import json
import os
import uuid
from datetime import datetime

# CONFIG
PROXY_URL = "http://llm_proxy:8080/v1/proxy"
LOG_DIR = "/logs/llm_logs"
SCENARIO_LOG = f"{LOG_DIR}/scenario_events.jsonl"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# 50 benign prompts - normal user questions
BENIGN_PROMPTS = [
    "What is the weather today?",
    "Tell me a fun fact about space.",
    "How do I cook pasta?",
    "What is the capital of France?",
    "Explain how rainbows work.",
    "Give me a simple Python function to calculate factorial.",
    "What is quantum entanglement?",
    "Tell me today's top news headline.",
    "Explain HTTP vs HTTPS.",
    "What is a REST API?",
    "Write a haiku about summer.",
    "How does a car engine work?",
    "What is the meaning of life?",
    "How do I improve my focus?",
    "Explain neural networks in simple terms.",
    "Tell me a joke.",
    "Explain recursion with an example.",
    "What are black holes?",
    "How do airplanes fly?",
    "Why is the sky blue?",
    "Explain photosynthesis.",
    "Give me a cookie recipe.",
    "Define machine learning.",
    "How do I meditate?",
    "What is Docker?",
    "What is Kubernetes?",
    "Explain TCP/IP.",
    "How do I improve sleep quality?",
    "What is inflation?",
    "Explain supply and demand.",
    "What is a prime number?",
    "Tell me about cats.",
    "Explain gravity.",
    "How do I make good coffee?",
    "What is the stock market?",
    "What is Rust programming language?",
    "Tell me how GPS works.",
    "What is entropy?",
    "Give me 3 healthy snacks.",
    "Explain blockchain.",
    "How does Wi-Fi work?",
    "What is a CPU?",
    "How does RAM work?",
    "Why do we dream?",
    "Explain evolution.",
    "What is cybersecurity?",
    "Tell me a bedtime story.",
    "How do I learn a new language?",
    "What is the difference between AI and ML?",
    "Explain how batteries work."
]

def log_event(event_type, data, session_id=None):
    """
    Unified logging function - same format as scenario_runner for consistency.
    Format matches BlueFlux telemetry model for easy correlation.
    """
    if session_id is None:
        session_id = f"normal-{uuid.uuid4().hex[:8]}"
    
    event = {
        "timestamp": time.time(),
        "timestamp_iso": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "event_type": event_type,  # "llm_request", "llm_response", "normal_activity"
        "source": "normal_behavior",  # Identifies this as normal traffic
        "data": data
    }
    
    with open(SCENARIO_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    print(f"[NORMAL] {event_type}: {json.dumps(data)[:100]}...")


def send_benign_prompt(session_id):
    """
    Sends a benign prompt to the LLM proxy and logs the interaction.
    """
    prompt = random.choice(BENIGN_PROMPTS)
    
    # Log the request
    log_event("llm_request", {
        "prompt": prompt,
        "prompt_type": "benign",
        "proxy_url": PROXY_URL
    }, session_id)
    
    try:
        # Send to proxy in the same format it expects
        response = requests.post(
            PROXY_URL,
            data={"message": prompt},  # Form-encoded, same as scenario_runner
            timeout=30,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code == 200:
            try:
                resp_data = response.json()
                # Extract message from GraphQL response format
                message = ""
                if "data" in resp_data:
                    node = resp_data.get("data", {}).get("node", {})
                    bot_msg = node.get("bot_response_message", {})
                    composed = bot_msg.get("composed_text", {})
                    content = composed.get("content", [])
                    if content and len(content) > 0:
                        message = content[0].get("text", "")
                
                log_event("llm_response", {
                    "status": "success",
                    "prompt": prompt,
                    "response_length": len(message),
                    "response_preview": message[:200] if message else "No message extracted"
                }, session_id)
                return True
            except Exception as e:
                log_event("llm_response", {
                    "status": "success",
                    "prompt": prompt,
                    "raw_response": response.text[:500],
                    "parse_error": str(e)
                }, session_id)
                return True
        else:
            log_event("llm_response", {
                "status": "error",
                "prompt": prompt,
                "error": f"HTTP {response.status_code}: {response.text[:200]}"
            }, session_id)
            return False
            
    except Exception as e:
        log_event("llm_response", {
            "status": "error",
            "prompt": prompt,
            "error": str(e)
        }, session_id)
        return False


def log_normal_activity(session_id):
    """
    Logs normal system activity (not LLM-related).
    """
    activities = [
        {"type": "user_login", "user_id": f"user_{random.randint(1000, 9999)}"},
        {"type": "page_view", "page": random.choice(["/home", "/dashboard", "/settings"])},
        {"type": "api_call", "endpoint": random.choice(["/api/users", "/api/data", "/api/config"])},
        {"type": "file_upload", "file_type": random.choice(["image", "document", "video"])},
        {"type": "search_query", "query": random.choice(["product", "documentation", "help"])},
    ]
    
    activity = random.choice(activities)
    log_event("normal_activity", activity, session_id)


def main():
    """
    Main loop: generates normal behavior patterns.
    Alternates between benign LLM prompts and normal system activities.
    """
    print("[*] Normal Behavior Simulator Started")
    print(f"[*] Logging to: {SCENARIO_LOG}")
    print("[*] Generating benign prompts and normal activity...")
    
    while True:
        session_id = f"normal-{int(time.time())}-{random.randint(1000, 9999)}"
        
        # Sometimes log normal activity
        if random.random() < 0.3:  # 30% chance
            log_normal_activity(session_id)
            time.sleep(random.uniform(0.5, 1.5))
        
        # Send a benign prompt
        send_benign_prompt(session_id)
        
        # Wait before next interaction (normal users don't spam)
        time.sleep(random.uniform(3, 8))  # 3-8 seconds between requests


if __name__ == "__main__":
    main()
