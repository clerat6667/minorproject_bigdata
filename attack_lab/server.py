#!/usr/bin/env python3
"""
Dedicated Cyber Range Attack Simulator & Traffic Generator API Server.
Runs on Port 8050 (or ATTACK_LAB_PORT).
Provides a dedicated Red Team control interface to launch controlled test traffic
against OWASP Juice Shop and verify detection in the Big Data SOC Dashboard.
"""

import os
import sys
import io
import time
import socket
import uvicorn
import requests
from contextlib import redirect_stdout, redirect_stderr
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

# Add attack_lab directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scenarios.normal_traffic import generate_normal_traffic
from scenarios.port_scan import run_port_scan
from scenarios.brute_force import run_brute_force
from scenarios.http_burst import run_http_burst
from scenarios.dns_anomaly import run_dns_anomaly
from scenarios.ioc_test import run_ioc_test
from scenarios.idor_probe import run_idor_probe
from scenarios.udp_burst import run_udp_burst
from scenarios.sqli_probe import run_sqli_probe
from scenarios.xss_probe import run_xss_probe
from scenarios.path_traversal import run_path_traversal
from scenarios.dns_nxdomain_flood import run_dns_nxdomain_flood
from scenarios.icmp_sweep import run_icmp_sweep
from scenarios.tcp_exhaustion import run_tcp_exhaustion
from scenarios.cti_suite import run_cti_suite
from scenarios.owasp_exploit import run_attack as run_owasp_exploit

PORT = int(os.getenv("ATTACK_LAB_PORT", 8050))
TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", 3000))
JUICE_SHOP_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
SOC_URL = os.getenv("SOC_URL", "http://localhost:8000")

app = FastAPI(
    title="Cyber Range Attack Simulator API",
    description="Dedicated Threat Generator for Big Data Analytics Lab",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCENARIO_HANDLERS = {
    "brute_force": run_brute_force,
    "sqli": run_sqli_probe,
    "idor": run_idor_probe,
    "xss": run_xss_probe,
    "path_traversal": run_path_traversal,
    "port_scan": run_port_scan,
    "tcp_exhaustion": run_tcp_exhaustion,
    "http_burst": run_http_burst,
    "dns_anomaly": run_dns_anomaly,
    "dns_nxdomain": run_dns_nxdomain_flood,
    "udp_burst": run_udp_burst,
    "icmp_sweep": run_icmp_sweep,
    "ioc_test": run_ioc_test,
    "cti_suite": run_cti_suite,
    "owasp_exploit": run_owasp_exploit,
    "normal": generate_normal_traffic
}

@app.get("/api/status")
def get_status():
    """Verify target and SOC connectivity."""
    target_ok = False
    try:
        r = requests.get(JUICE_SHOP_URL, timeout=1.5)
        target_ok = r.status_code in [200, 304]
    except Exception:
        # Check TCP socket as fallback
        try:
            s = socket.socket()
            s.settimeout(1.0)
            target_ok = (s.connect_ex((TARGET_HOST, TARGET_PORT)) == 0)
            s.close()
        except Exception:
            pass

    soc_ok = False
    try:
        r = requests.get(f"{SOC_URL}/api/health", timeout=1.5)
        soc_ok = (r.status_code == 200)
    except Exception:
        pass

    return {
        "target_url": JUICE_SHOP_URL,
        "target_online": target_ok,
        "soc_url": SOC_URL,
        "soc_online": soc_ok,
        "active_scenarios": list(SCENARIO_HANDLERS.keys())
    }

@app.post("/api/launch/{scenario_id}")
def launch_scenario(scenario_id: str):
    """Execute scenario and capture real stdout/stderr."""
    if scenario_id not in SCENARIO_HANDLERS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    fn = SCENARIO_HANDLERS[scenario_id]
    buffer = io.StringIO()
    t0 = time.time()
    
    try:
        with redirect_stdout(buffer), redirect_stderr(buffer):
            fn()
        output = buffer.getvalue()
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return {
            "scenario": scenario_id,
            "status": "SUCCESS",
            "execution_time_ms": elapsed_ms,
            "output": output
        }
    except Exception as e:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return {
            "scenario": scenario_id,
            "status": "ERROR",
            "execution_time_ms": elapsed_ms,
            "output": buffer.getvalue(),
            "error": str(e)
        }

# Serve Static UI
static_dir = os.path.join(BASE_DIR, "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Cyber Range Simulator API Active. static/index.html not found."}

if __name__ == "__main__":
    print(f"\n" + "="*70)
    print(f"[*] CYBER RANGE ATTACK SIMULATOR & THREAT GENERATOR UI")
    print(f"[*] Listening on: http://localhost:{PORT}")
    print(f"[*] Target Application: {JUICE_SHOP_URL}")
    print(f"[*] SOC Dashboard: {SOC_URL}")
    print("="*70 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
