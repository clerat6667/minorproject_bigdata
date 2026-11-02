"""
Real-Time Kafka Consumer Service & WebSocket Broadcaster.
Continuously consumes real security alerts, IDS events, and network telemetry from Kafka,
updates incident correlation, and streams updates to dashboard WebSockets.
"""

import os
import json
import time
import asyncio
import logging
import threading
from collections import deque
from typing import List, Set, Dict, Any, Optional
from fastapi import WebSocket


from ..models import NetworkEvent, ThreatAlert, CorrelatedIncident, SystemOverviewStats
from .incident_correlator import incident_correlator

logger = logging.getLogger("KafkaConsumerService")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

class KafkaStreamManager:
    def __init__(self):
        self.active_websockets: Set[WebSocket] = set()
        self.recent_events: deque = deque(maxlen=100)
        self.recent_alerts: deque = deque(maxlen=50)
        self.total_event_count: int = 0
        self.window_event_count: int = 0
        self.last_rate_time: float = time.time()
        self.current_eps: float = 0.0
        self.unique_sources: Set[str] = set()
        self.unique_destinations: Set[str] = set()
        self.running: bool = False
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        # Send initial snapshot
        snapshot = {
            "type": "SNAPSHOT",
            "stats": self.get_stats().model_dump(),
            "recent_alerts": [a.model_dump() for a in list(self.recent_alerts)[-20:]],
            "recent_events": [e.model_dump() for e in list(self.recent_events)[-20:]],
            "incidents": [i.model_dump() for i in incident_correlator.get_all_incidents()[:10]]
        }
        await websocket.send_text(json.dumps(snapshot))

    def disconnect_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    async def broadcast(self, message: dict):
        if not self.active_websockets:
            return
        msg_str = json.dumps(message)
        dead = []
        for ws in self.active_websockets:
            try:
                await ws.send_text(msg_str)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_websockets.discard(ws)

    def get_stats(self) -> SystemOverviewStats:
        now = time.time()
        elapsed = now - self.last_rate_time
        if elapsed >= 2.0:
            self.current_eps = round(self.window_event_count / elapsed, 1)
            self.window_event_count = 0
            self.last_rate_time = now

        critical = sum(1 for a in self.recent_alerts if a.severity in ["CRITICAL", "HIGH"])
        anomalies = sum(1 for a in self.recent_alerts if "ANOMALY" in a.threat_type or "BURST" in a.threat_type or "SCAN" in a.threat_type)
        iocs = sum(1 for a in self.recent_alerts if a.ioc_match)

        return SystemOverviewStats(
            total_events=self.total_event_count,
            events_per_sec=self.current_eps,
            active_alerts=len(self.recent_alerts),
            critical_alerts=critical,
            anomalies_detected=anomalies,
            ioc_matches=iocs,
            unique_sources=len(self.unique_sources),
            unique_destinations=len(self.unique_destinations)
        )

    def process_incoming_event(self, raw_data: dict):
        self.total_event_count += 1
        self.window_event_count += 1
        src = raw_data.get("source_ip", "0.0.0.0")
        dst = raw_data.get("destination_ip", "0.0.0.0")
        self.unique_sources.add(src)
        self.unique_destinations.add(dst)

        # Check if it's an alert or an event
        if "threat_type" in raw_data or "severity" in raw_data:
            try:
                alert = ThreatAlert(**raw_data)
                incident = incident_correlator.correlate_alert(alert)
                self.recent_alerts.appendleft(alert)

                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.broadcast({
                            "type": "NEW_ALERT",
                            "alert": alert.model_dump(),
                            "incident": incident.model_dump() if incident else None,
                            "stats": self.get_stats().model_dump()
                        }),
                        self.loop
                    )
            except Exception as e:
                logger.debug(f"Error parsing alert: {e}")
        else:
            try:
                event = NetworkEvent(**raw_data)
                self.recent_events.appendleft(event)

                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.broadcast({
                            "type": "NEW_EVENT",
                            "event": event.model_dump(),
                            "stats": self.get_stats().model_dump()
                        }),
                        self.loop
                    )
            except Exception as e:
                logger.debug(f"Error parsing network event: {e}")

    def start_consumer_worker(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.running = True

        def worker():
            from kafka import KafkaConsumer
            while self.running:
                try:
                    logger.info(f"Connecting background Kafka consumer to {KAFKA_BOOTSTRAP}...")
                    consumer = KafkaConsumer(
                        "threat-alerts", "suricata-alerts", "network-events",
                        bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
                        auto_offset_reset="latest",
                        enable_auto_commit=True,
                        group_id="backend-dashboard-consumer",
                        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                        request_timeout_ms=30000,
                        session_timeout_ms=10000
                    )
                    logger.info("Kafka consumer connected successfully! Streaming events...")
                    for message in consumer:
                        if not self.running:
                            break
                        self.process_incoming_event(message.value)
                except Exception as e:
                    logger.warning(f"Kafka consumer connection retry in 3s: {e}")
                    time.sleep(3)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

stream_manager = KafkaStreamManager()
