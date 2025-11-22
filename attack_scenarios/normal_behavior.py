"""
Simulate normal behavior of the system to compare everything
"""

import time
import json
import random
import requests

PROXY_BASE = "http://blueflux_proxy:8080"  # container-to-container name via docker compose
# If you run it directly on host, use "http://localhost:8080"

def send_ai_prompt():
    payload = {"message": "Normal app asking: what time is it?"}
    resp = requests.post(f"{PROXY_BASE}/v1/proxy", json=payload, timeout=30)
    print("[AI] Status:", resp.status_code)
    try:
        print("[AI] Response snippet:", resp.text[:200])
    except Exception:
        pass

def send_generic_event():
    # Simulated WAF/app event – not an AI prompt
    payload = {
        "event_type": "waf_alert",
        "rule_id": random.randint(1, 1000),
        "detail": "Simulated normal HTTP traffic from normal_behavior.py",
        "timestamp": time.time(),
    }
    resp = requests.post(f"{PROXY_BASE}/v1/proxy", json=payload, timeout=10)
    print("[GENERIC] Status:", resp.status_code)
    print("[GENERIC] Body:", resp.text[:200])

def main():
    while True:
        # Alternate between AI and generic calls
        send_generic_event()
        time.sleep(2)
        send_ai_prompt()
        time.sleep(5)

if __name__ == "__main__":
    main()
