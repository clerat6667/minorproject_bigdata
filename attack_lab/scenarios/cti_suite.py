#!/usr/bin/env python3
"""
Controlled Multi-Actor Cyber Threat Intelligence (CTI) Test Suite.
Generates network and DNS indicators associated with curated nation-state and
cybercriminal syndicates (APT-29, FIN7, Lazarus Group, DarkSide, Volt Typhoon).
Observed by: Zeek & Suricata (Rules 1000005 & 1000006)
Correlated by: Backend MISP/OpenCTI Engine & Spark Streaming -> Escalation to CRITICAL
"""

import os
import time
import socket

CTI_TEST_TARGETS = [
    ("198.51.100.77", 443, "APT-29 (Cozy Bear)", "Operation RedCloud C2 Beacon"),
    ("203.0.113.195", 80, "Lazarus Group", "Operation DarkHydra Scanner"),
    ("192.0.2.89", 443, "DarkSide / BlackCat", "Double Extortion Exfiltration Staging"),
    ("198.51.100.101", 443, "APT-28 (Fancy Bear)", "Operation Grizzly Espionage Recon"),
    ("198.51.100.55", 80, "Volt Typhoon", "Critical Infrastructure Living-off-the-Land")
]

CTI_DOMAINS = [
    ("malware-threat-lab.local", "FIN7", "Carbanak DNS Covert Tunnel"),
    ("lockbit-data-leak.local", "LockBit 3.0", "Affiliate Ransomware Leak Mirror"),
    ("c2-beacon.test", "Sandworm", "BlackEnergy Fast-Flux Domain")
]

def run_cti_suite():
    print(f"\n" + "="*70)
    print(f"[!] INITIATING COMPREHENSIVE CYBER THREAT INTELLIGENCE (CTI) TEST")
    print(f"    Testing Nation-State & Criminal Threat Actor IOCs")
    print("="*70 + "\n")

    # 1. IP Indicator Connections
    for ip, port, actor, campaign in CTI_TEST_TARGETS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            print(f"  [CTI PROBE] Simulating C2 communication to {ip}:{port} [{actor} - {campaign}]")
            s.connect_ex((ip, port))
        except Exception as e:
            pass
        finally:
            s.close()
        time.sleep(0.15)

    # 2. Domain Indicator Resolutions
    for domain, actor, desc in CTI_DOMAINS:
        try:
            print(f"  [CTI PROBE] Resolving Flagged Domain {domain} [{actor} - {desc}]")
            socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"      -> DNS query for flagged IOC domain emitted into network stack.")
        except Exception:
            pass
        time.sleep(0.15)

    print("\n[+] CTI Multi-Actor suite completed. Real IOC telemetry emitted.")
    print("[*] Backend CTI Engine will match indicators and escalate incidents to CRITICAL.\n")

if __name__ == "__main__":
    run_cti_suite()
