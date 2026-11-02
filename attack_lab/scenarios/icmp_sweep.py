#!/usr/bin/env python3
"""
Controlled ICMP Host Discovery Sweep & Echo Burst Scenario.
Dispatches standard ICMP Echo requests across the local subnet to simulate
adversary active discovery and host reconnaissance.
Observed by: Zeek (conn.log proto: ICMP), Suricata
Detected by: Spark Structured Streaming & Protocol Distribution Matrix
"""

import os
import time
import subprocess
import platform

TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1")

def run_icmp_sweep(count: int = 5):
    print(f"\n[!] INITIATING CONTROLLED ICMP HOST DISCOVERY PROBE against {TARGET_HOST}...")
    is_windows = platform.system().lower() == "windows"
    
    # Ping flag: -n on Windows, -c on Linux
    flag = "-n" if is_windows else "-c"
    cmd = ["ping", flag, str(count), TARGET_HOST]
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        lines = [line.strip() for line in res.stdout.split("\n") if line.strip() and ("reply from" in line.lower() or "bytes from" in line.lower())]
        for l in lines[:count]:
            print(f"  [ICMP ECHO] {l}")
        print(f"[+] ICMP discovery probe completed: {count} echo requests transmitted.")
        print(f"[*] Telemetry emitted with protocol=ICMP for network monitoring layer.")
        return True
    except Exception as e:
        print(f"  [*] ICMP status: {e}")
        return False

if __name__ == "__main__":
    run_icmp_sweep()
