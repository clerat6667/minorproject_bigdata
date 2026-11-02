"""
Cyber Threat Intelligence (CTI) & IOC Correlation Engine.
Provides MISP and OpenCTI compatible indicator management,
real-time IOC matching against network telemetry, and indicator lookups.
"""

import datetime
from typing import Dict, Optional, List
from ..models import CTIIndicator

class CTIEngine:
    def __init__(self):
        # Initial curated threat intelligence feed (MISP / OpenCTI indicators)
        self.indicators: Dict[str, CTIIndicator] = {
            "198.51.100.77": CTIIndicator(
                indicator="198.51.100.77",
                type="IP",
                threat_actor="APT-29 (Cozy Bear)",
                campaign="Operation RedCloud",
                severity="CRITICAL",
                confidence=0.98,
                description="Known command-and-control server beacon node observed in foreign infrastructure.",
                first_seen="2026-08-15T10:00:00Z",
                last_seen="2026-10-06T12:00:00Z"
            ),
            "203.0.113.195": CTIIndicator(
                indicator="203.0.113.195",
                type="IP",
                threat_actor="Lazarus Group",
                campaign="Operation DarkHydra",
                severity="HIGH",
                confidence=0.92,
                description="Malicious scanner IP associated with automated web application exploits.",
                first_seen="2026-09-01T08:30:00Z",
                last_seen="2026-10-05T20:15:00Z"
            ),
            "malware-threat-lab.local": CTIIndicator(
                indicator="malware-threat-lab.local",
                type="DOMAIN",
                threat_actor="FIN7",
                campaign="Carbanak Resurgence",
                severity="HIGH",
                confidence=0.90,
                description="Domain used for DNS covert tunneling and exfiltration staging.",
                first_seen="2026-09-12T14:20:00Z",
                last_seen="2026-10-06T09:45:00Z"
            ),
            "c2-beacon.test": CTIIndicator(
                indicator="c2-beacon.test",
                type="DOMAIN",
                threat_actor="Sandworm",
                campaign="BlackEnergy Variant",
                severity="CRITICAL",
                confidence=0.95,
                description="Fast-flux domain mapped to destructive ransomware telemetry.",
                first_seen="2026-07-20T11:00:00Z",
                last_seen="2026-10-04T18:00:00Z"
            ),
            "192.0.2.89": CTIIndicator(
                indicator="192.0.2.89",
                type="IP",
                threat_actor="DarkSide / BlackCat",
                campaign="Double Extortion Staging",
                severity="CRITICAL",
                confidence=0.99,
                description="Ransomware exfiltration staging gateway observed harvesting enterprise credentials.",
                first_seen="2026-09-05T06:15:00Z",
                last_seen="2026-10-06T14:30:00Z"
            ),
            "198.51.100.101": CTIIndicator(
                indicator="198.51.100.101",
                type="IP",
                threat_actor="APT-28 (Fancy Bear)",
                campaign="Operation Grizzly",
                severity="CRITICAL",
                confidence=0.97,
                description="Credential phishing and state-sponsored espionage reconnaissance source.",
                first_seen="2026-08-20T12:00:00Z",
                last_seen="2026-10-06T16:45:00Z"
            ),
            "lockbit-data-leak.local": CTIIndicator(
                indicator="lockbit-data-leak.local",
                type="DOMAIN",
                threat_actor="LockBit 3.0",
                campaign="Affiliate Data Leak",
                severity="CRITICAL",
                confidence=0.96,
                description="Tor mirror and exfiltration staging domain for stolen database archives.",
                first_seen="2026-09-18T09:10:00Z",
                last_seen="2026-10-06T18:00:00Z"
            ),
            "198.51.100.55": CTIIndicator(
                indicator="198.51.100.55",
                type="IP",
                threat_actor="Volt Typhoon",
                campaign="Critical Infrastructure Living-off-the-Land",
                severity="HIGH",
                confidence=0.94,
                description="SOHO proxy router leveraged for stealth persistence and network discovery.",
                first_seen="2026-09-22T04:00:00Z",
                last_seen="2026-10-06T20:10:00Z"
            )
        }

    def match_indicator(self, key: str) -> Optional[CTIIndicator]:
        """Check if an IP address, domain, or host matches a threat intelligence feed."""
        if not key:
            return None
        return self.indicators.get(key.strip().lower())

    def add_indicator(self, ind: CTIIndicator):
        self.indicators[ind.indicator.lower()] = ind

    def list_indicators(self) -> List[CTIIndicator]:
        return list(self.indicators.values())

cti_engine = CTIEngine()
