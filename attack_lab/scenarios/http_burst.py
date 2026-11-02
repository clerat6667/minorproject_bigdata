#!/usr/bin/env python3
"""
Controlled HTTP Request Burst / DoS-like Behavior.
Generates a rapid sequence of HTTP requests within a few seconds against OWASP Juice Shop.
Observed by: Zeek (http.log high request rate), Suricata (rule 1000003)
Detected by: Spark Structured Streaming (DOS_LIKE / Statistical Rate Burst)
"""

import os
import time
import requests
import concurrent.futures

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
JUICE_SHOP_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def send_request(idx):
    try:
        r = requests.get(f"{JUICE_SHOP_URL}/api/Products", timeout=1.5)
        return r.status_code
    except Exception:
        return 0

def run_http_burst(total_requests: int = 40):
    print(f"\n[!] INITIATING CONTROLLED HTTP REQUEST BURST ({total_requests} requests) against {JUICE_SHOP_URL}...")
    t0 = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(send_request, i) for i in range(total_requests)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
    duration = round(time.time() - t0, 2)
    rps = round(total_requests / max(0.01, duration), 1)
    print(f"[+] Completed {total_requests} requests in {duration}s (~{rps} req/sec)")
    print(f"[*] Burst traffic observed by monitoring and Big Data window aggregation layer.")

if __name__ == "__main__":
    run_http_burst()
