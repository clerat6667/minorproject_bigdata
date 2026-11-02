#!/usr/bin/env python3
"""
Attack Lab CLI Scenario Orchestrator.
Allows launching controlled cybersecurity scenarios against the lab target.
"""

import sys
import argparse
from scenarios.normal_traffic import generate_normal_traffic
from scenarios.port_scan import run_port_scan
from scenarios.brute_force import run_brute_force
from scenarios.http_burst import run_http_burst
from scenarios.dns_anomaly import run_dns_anomaly
from scenarios.ioc_test import run_ioc_test
from scenarios.idor_probe import run_idor_probe
from scenarios.udp_burst import run_udp_burst
from scenarios.sqli_probe import run_sqli_probe
from scenarios.owasp_exploit import run_attack as run_owasp_exploit

SCENARIOS = {
    "normal": generate_normal_traffic,
    "port_scan": run_port_scan,
    "brute_force": run_brute_force,
    "http_burst": run_http_burst,
    "dns_anomaly": run_dns_anomaly,
    "ioc_test": run_ioc_test,
    "idor": run_idor_probe,
    "udp_burst": run_udp_burst,
    "sqli": run_sqli_probe,
    "owasp_exploit": run_owasp_exploit
}

def main():
    parser = argparse.ArgumentParser(description="Controlled Attack Lab Orchestrator")
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="normal",
        help="Cybersecurity test scenario to execute"
    )
    args = parser.parse_args()

    if args.scenario == "all":
        print("[*] Running all attack lab scenarios in sequence...")
        for name, fn in SCENARIOS.items():
            print(f"\n==========================================")
            print(f"RUNNING SCENARIO: {name.upper()}")
            print(f"==========================================")
            try:
                fn()
            except Exception as e:
                print(f"Error in {name}: {e}")
    else:
        SCENARIOS[args.scenario]()

if __name__ == "__main__":
    main()
