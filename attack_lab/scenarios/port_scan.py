#!/usr/bin/env python3
"""
Controlled Port Scan Scenario.
Generates genuine TCP connection probes across a wide range of ports
against the lab target machine within a short timeframe.
Observed by: Zeek (conn.log), Suricata (eve.json)
Detected by: Spark Structured Streaming (PORT_SCAN, High unique destination ports)
"""

import os
import sys
import time
import socket

TARGET_HOST = os.getenv("TARGET_HOST", "localhost")

# Diverse set of common ports to scan
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    1433, 1521, 2049, 3000, 3306, 3389, 5432, 6379, 8000, 8080, 9092, 9870
]

def run_port_scan(target: str = TARGET_HOST, delay: float = 0.05):
    print(f"\n[!] INITIATING CONTROLLED PORT SCAN against {target}...")
    print(f"    Target Ports: {len(SCAN_PORTS)} ports across short interval")
    
    open_ports = []
    closed_ports = []
    
    t0 = time.time()
    for p in SCAN_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            res = s.connect_ex((target, p))
            if res == 0:
                open_ports.append(p)
                print(f"  [OPEN]   Port {p:5}/TCP")
            else:
                closed_ports.append(p)
                print(f"  [CLOSED] Port {p:5}/TCP")
        except Exception as e:
            closed_ports.append(p)
        finally:
            s.close()
        time.sleep(delay)
        
    duration = round(time.time() - t0, 2)
    print(f"[+] Scan completed in {duration}s!")
    print(f"    Open: {open_ports}")
    print(f"    Closed/Filtered: {len(closed_ports)} ports")
    print(f"[*] Telemetry transmitted across network stack to monitoring layer.")

if __name__ == "__main__":
    run_port_scan()
