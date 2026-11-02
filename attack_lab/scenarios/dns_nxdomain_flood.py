#!/usr/bin/env python3
"""
Controlled DNS DGA & NXDOMAIN Query Flood Scenario.
Simulates malware Domain Generation Algorithm (DGA) query floods and NXDOMAIN bursts.
Observed by: Zeek (dns.log rcode=3 NXDOMAIN), Suricata
Detected by: Spark Structured Streaming (DNS_ANOMALY classification)
"""

import os
import time
import socket
import random
import string

DNS_TARGET_COUNT = 25

def generate_dga_domain():
    # Pseudo-random pseudo-algorithm mimicking Conficker / Mirai DGA
    tld = random.choice([".info", ".top", ".local", ".xyz", ".cc"])
    length = random.randint(12, 22)
    label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))
    return f"{label}{tld}"

def run_dns_nxdomain_flood(count: int = DNS_TARGET_COUNT):
    print(f"\n[!] INITIATING CONTROLLED DNS DGA / NXDOMAIN FLOOD ({count} queries)...")
    nxdomains = 0
    
    for i in range(count):
        domain = generate_dga_domain()
        try:
            socket.gethostbyname(domain)
            print(f"  [{i+1}/{count}] Query {domain:28} -> RESOLVED")
        except socket.gaierror:
            nxdomains += 1
            if (i + 1) % 5 == 0 or i == count - 1:
                print(f"  [{i+1}/{count}] Query {domain:28} -> NXDOMAIN (RCODE 3)")
        except Exception as e:
            pass
        time.sleep(0.08)
        
    print(f"[+] DGA flood finished: {nxdomains} non-existent domain queries emitted.")
    print(f"[*] Telemetry transmitted into Zeek dns.log with failed lookup codes.")
    return nxdomains

if __name__ == "__main__":
    run_dns_nxdomain_flood()
