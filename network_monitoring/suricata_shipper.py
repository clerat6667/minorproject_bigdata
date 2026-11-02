#!/usr/bin/env python3
"""
Suricata Telemetry Shipper to Apache Kafka and Apache Hadoop HDFS.
Tails Suricata structured eve.json and streams real security alerts
and flow telemetry to Kafka topics and HDFS.
"""

import os
import sys
import time
import json
import uuid
import datetime
import logging
from kafka import KafkaProducer
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [SuricataShipper] %(message)s")
logger = logging.getLogger("SuricataShipper")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
EVE_JSON_PATH = os.getenv("EVE_JSON_PATH", "/var/log/suricata/eve.json")
WEBHDFS_URL = os.getenv("WEBHDFS_URL", "http://namenode:9870/webhdfs/v1")

def get_kafka_producer():
    for attempt in range(15):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                retries=5,
                acks="all"
            )
            logger.info(f"Connected to Kafka at {KAFKA_BOOTSTRAP}")
            return producer
        except Exception as e:
            logger.warning(f"Kafka connection attempt {attempt+1}/15 failed: {e}. Retrying in 3s...")
            time.sleep(3)
    logger.error("Could not connect to Kafka. Exiting.")
    sys.exit(1)

def append_to_hdfs(hdfs_path, data_line):
    try:
        url = f"{WEBHDFS_URL}{hdfs_path}?op=APPEND"
        resp = requests.post(url, allow_redirects=False, timeout=3)
        if resp.status_code == 307:
            redirect_url = resp.headers.get("Location")
            if redirect_url:
                requests.post(redirect_url, data=(data_line + "\n").encode("utf-8"), timeout=3)
    except Exception:
        pass

def tail_file(filepath):
    while not os.path.exists(filepath):
        time.sleep(1)
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.strip()

def process_eve_line(producer, line):
    try:
        raw = json.loads(line)
        event_type = raw.get("event_type")
        src_ip = raw.get("src_ip", "0.0.0.0")
        src_port = int(raw.get("src_port", 0) or 0)
        dest_ip = raw.get("dest_ip", "0.0.0.0")
        dest_port = int(raw.get("dest_port", 0) or 0)
        proto = raw.get("proto", "TCP").upper()
        ts = raw.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        # If it's a Suricata IDS alert
        if event_type == "alert":
            alert_info = raw.get("alert", {})
            signature = alert_info.get("signature", "Unknown Signature")
            severity_num = alert_info.get("severity", 3)
            # Map numeric severity to standard strings
            sev_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
            severity_str = sev_map.get(severity_num, "MEDIUM")

            alert = {
                "alert_id": f"suri-alt-{uuid.uuid4().hex[:10]}",
                "timestamp": ts,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "protocol": proto,
                "threat_type": "IDS_SIGNATURE_MATCH",
                "severity": severity_str,
                "confidence": 0.88,
                "detection_method": "SURICATA_RULE_ENGINE",
                "evidence": [
                    f"Suricata Signature: {signature}",
                    f"Category: {alert_info.get('category', 'Generic')}",
                    f"Signature ID: {alert_info.get('signature_id')}"
                ],
                "ioc_match": "IOC" in signature or "Malicious" in signature,
                "source": "SURICATA_EVE"
            }
            producer.send("suricata-alerts", key=src_ip, value=alert)
            producer.send("threat-alerts", key=src_ip, value=alert)
            logger.info(f"Published Suricata Alert: {signature} ({severity_str}) from {src_ip}")

        elif event_type == "flow":
            flow = raw.get("flow", {})
            event = {
                "event_id": f"suri-flw-{uuid.uuid4().hex[:10]}",
                "timestamp": ts,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "protocol": proto,
                "event_type": "FLOW",
                "bytes_sent": flow.get("bytes_toserver", 0),
                "bytes_received": flow.get("bytes_toclient", 0),
                "duration": flow.get("age", 0),
                "source": "SURICATA_FLOW"
            }
            producer.send("network-events", key=src_ip, value=event)

        # Archive raw record to HDFS
        append_to_hdfs(f"/security-data/raw/suricata/eve_{datetime.date.today()}.json", line)
    except Exception as e:
        logger.debug(f"Error parsing eve.json line: {e}")

def run():
    producer = get_kafka_producer()
    logger.info(f"Tailing Suricata eve.json at {EVE_JSON_PATH}")
    for line in tail_file(EVE_JSON_PATH):
        if line:
            process_eve_line(producer, line)

if __name__ == "__main__":
    run()
