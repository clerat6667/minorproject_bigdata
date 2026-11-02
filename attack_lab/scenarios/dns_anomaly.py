#!/usr/bin/env python3
"""
Controlled DNS Anomaly Scenario.
Generates unusual high-frequency DNS query bursts, NXDOMAINs, and
high-entropy subdomains simulating DNS tunneling / exfiltration.
Observed by: Zeek (dns.log), Suricata (eve.json)
Detected by: Spark Structured Streaming (DNS_ANOMALY)
"""

import os
import time
import socket
import random
import string

DNS_SERVER = os.getenv("DNS_SERVER", "127.0.0.1")

def random_subdomain(length: int = 24):
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def run_dns_anomaly(count: int = 20):
    print(f"\n[!] INITIATING CONTROLLED DNS ANOMALY BURST ({count} queries)...")
    
    for i in range(count):
        domain = f"{random_subdomain(20)}.tunnel-test.local"
        try:
            # Query domain via standard socket resolver
            socket.gethostbyname(domain)
            print(f"  [{i+1}/{count}] Query: {domain} -> Resolved")
        except socket.gaierror:
            print(f"  [{i+1}/{count}] Query: {domain} -> NXDOMAIN (Expected)")
        except Exception as e:
            print(f"  [{i+1}/{count}] Query: {domain} -> Notice: {e}")
        time.sleep(0.1)
        
    print(f"[+] DNS anomaly pattern generated. Real telemetry emitted to Zeek dns.log.")

if __name__ == "__main__":
    run_dns_anomaly()
