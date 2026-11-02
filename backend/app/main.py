"""
Main FastAPI Application Entrypoint.
Provides REST APIs for:
  - System Overview & Live Metrics
  - System Health Probes (Real socket/HTTP status)
  - Interactive Command Center Diagnostics
  - Historical Alerts, Events, and Incidents
  - Threat Intelligence (MISP/OpenCTI indicators)
  - WebSocket Stream at /ws/stream
"""

import os
import asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .models import (
    CommandRequest, CommandResponse, SystemOverviewStats,
    ThreatAlert, NetworkEvent, CorrelatedIncident, CTIIndicator
)
from .services.health_checker import check_all_services
from .services.command_executor import execute_command
from .services.kafka_consumer_service import stream_manager
from .services.incident_correlator import incident_correlator
from .services.cti_engine import cti_engine
from .services.pipeline_service import get_complete_pipeline_analytics
from .services.excel_exporter import generate_security_statement_excel
from .services.text_auditor import generate_formal_audit_text

app = FastAPI(
    title="Real-Time Cyber Threat Detection & Big Data Analytics API",
    description="Department of Artificial Intelligence and Data Science - Big Data Cybersecurity Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    loop = asyncio.get_running_loop()
    stream_manager.start_consumer_worker(loop)

@app.get("/api/health")
def get_health():
    """True service health check across Kafka, HDFS, Spark, Zeek, Suricata, etc."""
    return check_all_services()

@app.get("/api/stats", response_model=SystemOverviewStats)
def get_stats():
    """Live aggregated cybersecurity metrics."""
    return stream_manager.get_stats()

@app.get("/api/alerts")
def get_recent_alerts():
    """Get recent threat alerts."""
    return list(stream_manager.recent_alerts)

@app.get("/api/events")
def get_recent_events():
    """Get recent network telemetry events."""
    return list(stream_manager.recent_events)

@app.get("/api/incidents")
def get_incidents():
    """Get correlated high-confidence security incidents."""
    return incident_correlator.get_all_incidents()

@app.get("/api/cti/indicators")
def get_cti_indicators():
    """Get active MISP/OpenCTI threat intelligence catalog."""
    return cti_engine.list_indicators()

@app.get("/api/pipeline")
def get_pipeline_endpoint():
    """Get real-time Big Data Pipeline & HDFS analytics."""
    return get_complete_pipeline_analytics()

@app.get("/api/export/excel")
def export_excel_statement():
    """Generate and download genuine executive security audit statement in Excel (.xlsx) format."""
    stats = stream_manager.get_stats().model_dump()
    incidents = [inc.model_dump() for inc in incident_correlator.get_all_incidents()]
    alerts = [alt.model_dump() for alt in stream_manager.recent_alerts]
    events = [evt.model_dump() for evt in stream_manager.recent_events]
    indicators = [ind.model_dump() for ind in cti_engine.list_indicators()]
    pipeline = get_complete_pipeline_analytics()
    
    excel_stream = generate_security_statement_excel(
        stats=stats,
        incidents=incidents,
        alerts=alerts,
        events=events,
        cti_indicators=indicators,
        pipeline=pipeline
    )
    filename = f"CyberSecurity_SOC_Audit_Statement_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return StreamingResponse(
        excel_stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/export/audit-text")
def export_audit_text():
    """Generate and download a strict, plain-text formal audit report."""
    stats = stream_manager.get_stats().model_dump()
    incidents = [inc.model_dump() for inc in incident_correlator.get_all_incidents()]
    alerts = [alt.model_dump() for alt in stream_manager.recent_alerts]
    events = [evt.model_dump() for evt in stream_manager.recent_events]
    pipeline = get_complete_pipeline_analytics()
    
    text_stream = generate_formal_audit_text(
        stats=stats,
        incidents=incidents,
        alerts=alerts,
        events=events,
        pipeline=pipeline
    )
    filename = f"Formal_Audit_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    return StreamingResponse(
        text_stream,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/powerbi/dataset")
def get_powerbi_dataset():
    """Power BI Web Connector endpoint - returns structured tabular telemetry for Power BI import."""
    stats = stream_manager.get_stats().model_dump()
    incidents = [inc.model_dump() for inc in incident_correlator.get_all_incidents()]
    alerts = [alt.model_dump() for alt in stream_manager.recent_alerts]
    events = [evt.model_dump() for evt in stream_manager.recent_events]
    indicators = [ind.model_dump() for ind in cti_engine.list_indicators()]
    
    tabular_records = []
    # Alerts table for Power BI
    for a in alerts:
        tabular_records.append({
            "id": a.get("alert_id"),
            "record_type": "THREAT_ALERT",
            "timestamp": a.get("timestamp"),
            "source_ip": a.get("source_ip"),
            "destination_ip": a.get("destination_ip"),
            "threat_classification": a.get("threat_type"),
            "severity": a.get("severity"),
            "confidence_score": a.get("confidence", 0.0),
            "detection_engine": a.get("detection_method"),
            "is_ioc_match": a.get("ioc_match", False),
            "incident_id": a.get("incident_id") or "NONE",
            "evidence": "; ".join(a.get("evidence", []))
        })
    # Events table for Power BI
    for e in events:
        tabular_records.append({
            "id": e.get("event_id"),
            "record_type": "NETWORK_FLOW",
            "timestamp": e.get("timestamp"),
            "source_ip": e.get("source_ip"),
            "destination_ip": e.get("destination_ip"),
            "threat_classification": "BENIGN_FLOW",
            "severity": "NORMAL",
            "confidence_score": 1.0,
            "detection_engine": e.get("source", "ZEEK_NSM"),
            "is_ioc_match": False,
            "incident_id": "NONE",
            "evidence": f"Protocol: {e.get('protocol', 'TCP')}, Bytes Sent: {e.get('bytes_sent', 0)}"
        })

    return {
        "metadata": {
            "title": "Big Data Cybersecurity Analytics Power BI Dataset",
            "extracted_at": datetime.utcnow().isoformat(),
            "total_records": len(tabular_records),
            "open_incidents_count": len(incidents),
            "stats": stats
        },
        "records": tabular_records,
        "incidents": incidents,
        "cti_catalog": indicators
    }

@app.post("/api/command", response_model=CommandResponse)
def run_command_endpoint(req: CommandRequest):
    """Execute real diagnostic command in the Command Center."""
    return execute_command(req.command)

@app.websocket("/ws/stream")
async def websocket_stream_endpoint(websocket: WebSocket):
    """Real-time event and alert stream via WebSocket."""
    await stream_manager.connect_websocket(websocket)
    try:
        while True:
            # Keepalive / ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        stream_manager.disconnect_websocket(websocket)
    except Exception:
        stream_manager.disconnect_websocket(websocket)

# Serve dashboard static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

