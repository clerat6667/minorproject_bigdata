#!/usr/bin/env python3
"""
Normal Traffic Generator for Baseline Establishment.
Generates legitimate HTTP browsing, API calls, and standard connections
against the local lab target.
"""

import os
import time
import random
import requests
import socket

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
JUICE_SHOP_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

NORMAL_ENDPOINTS = [
    "/",
    "/rest/admin/application-version",
    "/api/Products",
    "/api/Quantitys",
    "/rest/languages",
    "/assets/public/favicon_js.ico"
]

def generate_normal_traffic(count: int = 15, delay: float = 0.5):
    print(f"[*] Starting Normal Traffic generation against {JUICE_SHOP_URL}...")
    success = 0
    for i in range(count):
        ep = random.choice(NORMAL_ENDPOINTS)
        url = f"{JUICE_SHOP_URL}{ep}"
        try:
            r = requests.get(url, timeout=3.0)
            success += 1
            print(f"  [{i+1}/{count}] Normal GET {ep} -> HTTP {r.status_code}")
        except Exception as e:
            # If juice-shop is not up yet, try local socket
            print(f"  [{i+1}/{count}] Connection notice ({ep}): {e}")
        time.sleep(delay)
    print(f"[+] Completed normal traffic run ({success}/{count} successful).")

if __name__ == "__main__":
    generate_normal_traffic()
