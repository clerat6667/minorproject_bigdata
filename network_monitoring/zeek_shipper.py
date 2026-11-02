#!/usr/bin/env python3
"""
Zeek Telemetry Shipper to Apache Kafka and Apache Hadoop HDFS.
Tails Zeek structured JSON logs (conn.log, dns.log, http.log, notice.log)
and streams real events to Kafka topics and HDFS raw storage.
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ZeekShipper] %(message)s")
logger = logging.getLogger("ZeekShipper")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/var/log/zeek")
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
    """Write raw log line to HDFS raw telemetry partition."""
    try:
        url = f"{WEBHDFS_URL}{hdfs_path}?op=APPEND"
        resp = requests.post(url, allow_redirects=False, timeout=3)
        if resp.status_code == 307:
            redirect_url = resp.headers.get("Location")
            if redirect_url:
                requests.post(redirect_url, data=(data_line + "\n").encode("utf-8"), timeout=3)
    except Exception:
        pass  # Non-blocking for HDFS transient network

def tail_file(filepath):
    """Generator to yield new lines appended to a file (like tail -F)."""
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

def process_conn_log(producer, line):
    try:
        raw = json.loads(line)
        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": raw.get("ts", datetime.datetime.now(datetime.timezone.utc).isoformat()),
            "source_ip": raw.get("id.orig_h", "0.0.0.0"),
            "source_port": int(raw.get("id.orig_p", 0)),
            "destination_ip": raw.get("id.resp_h", "0.0.0.0"),
            "destination_port": int(raw.get("id.resp_p", 0)),
            "protocol": raw.get("proto", "TCP").upper(),
            "event_type": "CONNECTION",
            "bytes_sent": int(raw.get("orig_bytes") or raw.get("orig_ip_bytes") or 0),
            "bytes_received": int(raw.get("resp_bytes") or raw.get("resp_ip_bytes") or 0),
            "duration": float(raw.get("duration", 0.0) or 0.0),
            "conn_state": raw.get("conn_state", "UNK"),
            "source": "ZEEK_CONN",
            "metadata": raw
        }
        producer.send("network-events", key=event["source_ip"], value=event)
        producer.send("zeek-events", key=event["event_id"], value=event)
        append_to_hdfs(f"/security-data/raw/zeek/conn_{datetime.date.today()}.json", line)
    except Exception as e:
        logger.debug(f"Error parsing conn line: {e}")

def process_dns_log(producer, line):
    try:
        raw = json.loads(line)
        event = {
            "event_id": f"dns-{uuid.uuid4().hex[:12]}",
            "timestamp": raw.get("ts", datetime.datetime.now(datetime.timezone.utc).isoformat()),
            "source_ip": raw.get("id.orig_h", "0.0.0.0"),
            "source_port": int(raw.get("id.orig_p", 0)),
            "destination_ip": raw.get("id.resp_h", "0.0.0.0"),
            "destination_port": int(raw.get("id.resp_p", 53)),
            "protocol": "UDP",
            "event_type": "DNS_QUERY",
            "query": raw.get("query", ""),
            "qtype_name": raw.get("qtype_name", "A"),
            "rcode_name": raw.get("rcode_name", "NOERROR"),
            "answers": raw.get("answers", []),
            "source": "ZEEK_DNS",
            "metadata": raw
        }
        producer.send("dns-events", key=event["source_ip"], value=event)
        producer.send("network-events", key=event["source_ip"], value=event)
        append_to_hdfs(f"/security-data/raw/zeek/dns_{datetime.date.today()}.json", line)
    except Exception as e:
        logger.debug(f"Error parsing dns line: {e}")

def process_http_log(producer, line):
    try:
        raw = json.loads(line)
        event = {
            "event_id": f"http-{uuid.uuid4().hex[:12]}",
            "timestamp": raw.get("ts", datetime.datetime.now(datetime.timezone.utc).isoformat()),
            "source_ip": raw.get("id.orig_h", "0.0.0.0"),
            "source_port": int(raw.get("id.orig_p", 0)),
            "destination_ip": raw.get("id.resp_h", "0.0.0.0"),
            "destination_port": int(raw.get("id.resp_p", 80)),
            "protocol": "TCP",
            "event_type": "HTTP_REQUEST",
            "http_method": raw.get("method", "GET"),
            "http_host": raw.get("host", ""),
            "http_uri": raw.get("uri", "/"),
            "status_code": int(raw.get("status_code", 0) or 0),
            "user_agent": raw.get("user_agent", ""),
            "source": "ZEEK_HTTP",
            "metadata": raw
        }
        producer.send("http-events", key=event["source_ip"], value=event)
        producer.send("network-events", key=event["source_ip"], value=event)
        append_to_hdfs(f"/security-data/raw/zeek/http_{datetime.date.today()}.json", line)
    except Exception as e:
        logger.debug(f"Error parsing http line: {e}")

def run():
    producer = get_kafka_producer()
    import threading

    def monitor(filename, handler):
        path = os.path.join(ZEEK_LOG_DIR, filename)
        logger.info(f"Starting file watcher on {path}")
        for line in tail_file(path):
            if line:
                handler(producer, line)

    threads = [
        threading.Thread(target=monitor, args=("conn.log", process_conn_log), daemon=True),
        threading.Thread(target=monitor, args=("dns.log", process_dns_log), daemon=True),
        threading.Thread(target=monitor, args=("http.log", process_http_log), daemon=True),
    ]

    for t in threads:
        t.start()

    logger.info("Zeek Telemetry Shipper actively streaming logs to Kafka.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        producer.flush()
        producer.close()

if __name__ == "__main__":
    run()
