"""
Pydantic Data Models for Big Data Cybersecurity Platform.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class NetworkEvent(BaseModel):
    event_id: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    event_type: str
    bytes_sent: int = 0
    bytes_received: int = 0
    duration: float = 0.0
    status_code: Optional[int] = None
    http_uri: Optional[str] = None
    query: Optional[str] = None
    source: Optional[str] = "SYSTEM"
    metadata: Optional[Dict[str, Any]] = None

class ThreatAlert(BaseModel):
    alert_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: str
    confidence: float
    detection_method: str
    evidence: List[str]
    ioc_match: bool = False
    incident_id: Optional[str] = None
    source: Optional[str] = "SPARK_STREAMING"
    raw_metrics: Optional[Dict[str, Any]] = None

class CorrelatedIncident(BaseModel):
    incident_id: str
    first_seen: str
    last_seen: str
    source_ips: List[str]
    destination_ips: List[str]
    threat_types: List[str]
    iocs: List[str] = []
    severity: str
    confidence: float
    status: str = "OPEN"
    evidence: List[str]
    alert_count: int = 1

class ServiceHealth(BaseModel):
    name: str
    status: str  # ONLINE, OFFLINE, DEGRADED
    latency_ms: Optional[float] = None
    details: Optional[str] = None
    error: Optional[str] = None

class SystemOverviewStats(BaseModel):
    total_events: int = 0
    events_per_sec: float = 0.0
    active_alerts: int = 0
    critical_alerts: int = 0
    anomalies_detected: int = 0
    ioc_matches: int = 0
    unique_sources: int = 0
    unique_destinations: int = 0

class CommandRequest(BaseModel):
    command: str
    args: Optional[List[str]] = []

class CommandResponse(BaseModel):
    command: str
    status: str  # SUCCESS, ERROR
    execution_time_ms: float
    output: str
    error: Optional[str] = None

class CTIIndicator(BaseModel):
    indicator: str
    type: str  # IP, DOMAIN, URL, HASH
    threat_actor: str
    campaign: str
    severity: str
    confidence: float
    description: str
    first_seen: str
    last_seen: str
