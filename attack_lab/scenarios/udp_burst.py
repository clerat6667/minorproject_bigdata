#!/usr/bin/env python3
"""
Controlled UDP Protocol Anomaly Burst Scenario.
Transmits rapid sequences of UDP packets towards target ports to generate
non-TCP connection flows and protocol distribution anomalies.
Observed by: Zeek (conn.log proto: UDP), Suricata
Detected by: Spark Structured Streaming (Protocol shift & volumetric burst)
"""

import os
import time
import socket
import random

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
UDP_PORTS = [5353, 5000, 3000, 8080, 9000, 12345]

def run_udp_burst(packet_count: int = 30, delay: float = 0.05):
    print(f"\n[!] INITIATING CONTROLLED UDP PROTOCOL ANOMALY BURST ({packet_count} packets)...")
    print(f"    Target Host: {TARGET_HOST}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent_count = 0
    
    for i in range(packet_count):
        port = random.choice(UDP_PORTS)
        # 64-byte pseudo-random payload simulating unconventional protocol traffic
        payload = bytes([random.randint(0, 255) for _ in range(64)])
        try:
            sock.sendto(payload, (TARGET_HOST, port))
            sent_count += 1
            if (i + 1) % 5 == 0 or i == packet_count - 1:
                print(f"  [{i+1}/{packet_count}] Sent 64-byte UDP datagram to {TARGET_HOST}:{port}")
        except Exception as e:
            print(f"  [{i+1}/{packet_count}] UDP Send error to port {port}: {e}")
        time.sleep(delay)
        
    sock.close()
    print(f"[+] UDP anomaly sequence finished: {sent_count} packets dispatched.")
    print(f"[*] Telemetry transmitted into Zeek conn.log with protocol=UDP.")
    return sent_count

if __name__ == "__main__":
    run_udp_burst()
