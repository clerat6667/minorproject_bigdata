#!/usr/bin/env python3
"""
Controlled Known IOC Test Scenario.
Generates network connection attempts and DNS inquiries referencing
curated Cyber Threat Intelligence (CTI) indicators (e.g., APT-29 C2 IP 198.51.100.77).
Observed by: Zeek & Suricata (rule 1000005 & 1000006)
Correlated by: Backend CTI Engine & Spark Streaming -> [IOC MATCH / CRITICAL]
"""

import os
import time
import socket

IOC_IP = "198.51.100.77"
IOC_DOMAIN = "malware-threat-lab.local"

def run_ioc_test():
    print(f"\n[!] INITIATING CONTROLLED CTI IOC TEST...")
    print(f"    Testing Flagged Indicator IP:     {IOC_IP} (APT-29 C2 Beacon)")
    print(f"    Testing Flagged Indicator Domain: {IOC_DOMAIN} (FIN7 Staging)")
    
    # 1. TCP connection attempt to IOC IP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        print(f"  [*] Attempting connection to IOC IP {IOC_IP}:443...")
        s.connect_ex((IOC_IP, 443))
    except Exception as e:
        print(f"  [*] Packet routed towards {IOC_IP}: {e}")
    finally:
        s.close()

    # 2. DNS query for IOC domain
    try:
        print(f"  [*] Resolving known malicious CTI domain {IOC_DOMAIN}...")
        socket.gethostbyname(IOC_DOMAIN)
    except socket.gaierror:
        print(f"  [+] DNS packet for {IOC_DOMAIN} emitted into network stack.")
    except Exception as e:
        print(f"  [*] DNS status: {e}")

    print(f"[+] IOC telemetry dispatched! Should trigger CTI match and incident escalation.")

if __name__ == "__main__":
    run_ioc_test()
