import time
import random
import requests
import json

PROXY_BASE = "http://blueflux_proxy:8080"

# 50 benign prompts
BENIGN_PROMPTS = [
    "What is the weather today?",
    "Tell me a fun fact about space.",
    "How do I cook pasta?",
    "What is the capital of France?",
    "Explain how rainbows work.",
    "Give me a simple Python function.",
    "What is quantum entanglement?",
    "Tell me today's top news headline.",
    "Explain HTTP vs HTTPS.",
    "What is a REST API?",
    "Write a haiku about summer.",
    "How does a car engine work?",
    "What is the meaning of life?",
    "How do I improve my focus?",
    "Explain neural networks.",
    "Tell me a joke.",
    "Explain recursion.",
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
    "Explain recursion again.",
    "Tell me how GPS works.",
    "What is entropy?",
    "Give me 3 healthy snacks.",
    "Explain blockchain.",
    "How does Wi-Fi work?",
    "What is a CPU?",
    "How does RAM work?",
    "Why do we dream?",
    "Explain evolution.",
    "Give me a random number.",
    "What is cybersecurity?",
    "Tell me a bedtime story."
]

def send_ai_prompt():
    prompt = random.choice(BENIGN_PROMPTS)
    payload = {"message": prompt}
    resp = requests.post(f"{PROXY_BASE}/v1/proxy", json=payload, timeout=30)
    print("\n[AI] Prompt:", prompt)
    print("[AI] Status:", resp.status_code)
    print("[AI] Snippet:", resp.text[:150])

def send_generic_event():
    payload = {
        "event_type": "system_log",
        "severity": random.choice(["INFO", "WARN"]),
        "component": random.choice(["auth", "billing", "ui", "cache"]),
        "message": "Routine activity",
        "timestamp": time.time(),
    }
    resp = requests.post(f"{PROXY_BASE}/v1/proxy", json=payload)
    print("\n[GENERIC] Event sent | Status:", resp.status_code)

def main():
    while True:
        send_generic_event()
        time.sleep(random.uniform(1, 3))
        send_ai_prompt()
        time.sleep(random.uniform(2, 4))

if __name__ == "__main__":
    main()
