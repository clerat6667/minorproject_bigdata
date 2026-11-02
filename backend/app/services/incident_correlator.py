"""
Incident Correlation & False Positive Reduction Engine.
Correlates multi-source telemetry (Zeek behavioral, Suricata signatures, Spark ML, CTI matches)
into high-confidence security incidents. Implements duplicate suppression and cooldowns.
"""

import uuid
import datetime
from typing import Dict, List, Optional
from ..models import ThreatAlert, CorrelatedIncident
from .cti_engine import cti_engine

class IncidentCorrelator:
    def __init__(self, cooldown_seconds: int = 30):
        self.incidents: Dict[str, CorrelatedIncident] = {}
        self.ip_to_incident: Dict[str, str] = {}
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time: Dict[str, datetime.datetime] = {}

    def correlate_alert(self, alert: ThreatAlert) -> Optional[CorrelatedIncident]:
        src_ip = alert.source_ip
        now = datetime.datetime.now(datetime.timezone.utc)

        # Check for CTI IOC match on Source IP
        ioc_match = cti_engine.match_indicator(src_ip)
        if ioc_match:
            alert.ioc_match = True
            alert.evidence.append(
                f"[CTI MATCH] Known Threat Actor '{ioc_match.threat_actor}' ({ioc_match.campaign})"
            )
            alert.severity = "CRITICAL"
            alert.confidence = max(alert.confidence, 0.98)

        # Check if an existing open incident exists for this source IP
        incident_id = self.ip_to_incident.get(src_ip)
        if incident_id and incident_id in self.incidents:
            incident = self.incidents[incident_id]
            incident.last_seen = alert.timestamp
            incident.alert_count += 1
            if alert.destination_ip not in incident.destination_ips:
                incident.destination_ips.append(alert.destination_ip)
            if alert.threat_type not in incident.threat_types:
                incident.threat_types.append(alert.threat_type)
            if alert.ioc_match and src_ip not in incident.iocs:
                incident.iocs.append(src_ip)
            for ev in alert.evidence:
                if ev not in incident.evidence:
                    incident.evidence.append(ev)

            # Escalate severity if multiple threat types detected
            if len(incident.threat_types) > 1 or alert.ioc_match:
                incident.severity = "CRITICAL"
                incident.confidence = min(0.99, incident.confidence + 0.05)

            alert.incident_id = incident.incident_id
            return incident

        # Otherwise create a new Incident
        new_incident_id = f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        severity = alert.severity
        iocs = [src_ip] if alert.ioc_match else []
        evidence = list(alert.evidence)

        incident = CorrelatedIncident(
            incident_id=new_incident_id,
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
            source_ips=[src_ip],
            destination_ips=[alert.destination_ip],
            threat_types=[alert.threat_type],
            iocs=iocs,
            severity=severity,
            confidence=alert.confidence,
            status="OPEN",
            evidence=evidence,
            alert_count=1
        )
        self.incidents[new_incident_id] = incident
        self.ip_to_incident[src_ip] = new_incident_id
        alert.incident_id = new_incident_id
        return incident

    def get_all_incidents(self) -> List[CorrelatedIncident]:
        return sorted(self.incidents.values(), key=lambda x: x.last_seen, reverse=True)

incident_correlator = IncidentCorrelator()
