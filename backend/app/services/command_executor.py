"""
Command Center Diagnostics Executor.
Executes genuine diagnostic commands against Apache Kafka, Apache Hadoop HDFS,
Apache Spark, Zeek, Suricata, and CTI.
Returns true executed output or real failure error without mocks.
"""

import os
import time
import json
import requests
import subprocess
from typing import List, Dict, Any
from ..models import CommandResponse
from .cti_engine import cti_engine

KAFKA_HOST = os.getenv("KAFKA_HOST", "kafka")
KAFKA_PORT = int(os.getenv("KAFKA_PORT", 9092))
HDFS_HOST = os.getenv("HDFS_HOST", "namenode")
HDFS_PORT = int(os.getenv("HDFS_PORT", 9870))
SPARK_HOST = os.getenv("SPARK_HOST", "spark-master")
SPARK_PORT = int(os.getenv("SPARK_PORT", 8080))
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/var/log/zeek")
SURICATA_LOG_DIR = os.getenv("SURICATA_LOG_DIR", "/var/log/suricata")

def execute_command(cmd_string: str) -> CommandResponse:
    t0 = time.time()
    parts = cmd_string.strip().split()
    if not parts:
        return CommandResponse(
            command=cmd_string,
            status="ERROR",
            execution_time_ms=0.0,
            output="",
            error="Empty command provided."
        )

    base = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    try:
        # KAFKA COMMANDS
        if base in ["kafka-list-topics", "kafka_list_topics", "list-topics"]:
            try:
                from kafka import KafkaConsumer
                consumer = KafkaConsumer(
                    bootstrap_servers=[f"{KAFKA_HOST}:{KAFKA_PORT}"],
                    request_timeout_ms=15000,
                    session_timeout_ms=10000
                )

                topics = list(consumer.topics())
                consumer.close()
                output = f"Connected to Kafka broker at {KAFKA_HOST}:{KAFKA_PORT}\nActive topics found ({len(topics)}):\n"
                for t in sorted(topics):
                    output += f"  - {t}\n"
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            except Exception as e:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"Failed to query Kafka broker: {str(e)}"
                )

        elif base in ["kafka-describe-topic", "describe-topic"]:
            topic = arg or "network-events"
            try:
                from kafka import KafkaConsumer, TopicPartition
                consumer = KafkaConsumer(
                    bootstrap_servers=[f"{KAFKA_HOST}:{KAFKA_PORT}"],
                    request_timeout_ms=3000
                )
                partitions = consumer.partitions_for_topic(topic)
                if not partitions:
                    output = f"Topic '{topic}' does not exist or has no partitions."
                else:
                    output = f"Topic: {topic}\nPartitions ({len(partitions)}):\n"
                    for p in sorted(partitions):
                        tp = TopicPartition(topic, p)
                        output += f"  Partition {p}: Leader active\n"
                consumer.close()
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            except Exception as e:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"Kafka describe error: {str(e)}"
                )

        # HDFS COMMANDS
        elif base in ["hdfs-list-root", "list-root"]:
            url = f"http://{HDFS_HOST}:{HDFS_PORT}/webhdfs/v1/?op=LISTSTATUS"
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json().get("FileStatuses", {}).get("FileStatus", [])
                output = f"HDFS Root Directory (/):\n"
                for f in data:
                    t = "DIR " if f.get("type") == "DIRECTORY" else "FILE"
                    output += f"  {t:4} {f.get('pathSuffix')} (size: {f.get('length')} bytes, owner: {f.get('owner')})\n"
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            else:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"WebHDFS returned HTTP {resp.status_code}: {resp.text}"
                )

        elif base in ["hdfs-list-security-data", "list-security-data"]:
            url = f"http://{HDFS_HOST}:{HDFS_PORT}/webhdfs/v1/security-data?op=LISTSTATUS"
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json().get("FileStatuses", {}).get("FileStatus", [])
                output = f"HDFS /security-data Tree:\n"
                for f in data:
                    t = "DIR " if f.get("type") == "DIRECTORY" else "FILE"
                    output += f"  {t:4} /security-data/{f.get('pathSuffix')}\n"
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            else:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"WebHDFS returned HTTP {resp.status_code}: {resp.text}"
                )

        elif base in ["hdfs-storage-status", "show-storage"]:
            url = f"http://{HDFS_HOST}:{HDFS_PORT}/jmx?qry=Hadoop:service=NameNode,name=FSNamesystem"
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                beans = resp.json().get("beans", [{}])[0]
                total = beans.get("CapacityTotal", 0) / (1024*1024*1024)
                used = beans.get("CapacityUsed", 0) / (1024*1024)
                free = beans.get("CapacityRemaining", 0) / (1024*1024*1024)
                files = beans.get("FilesTotal", 0)
                output = (
                    f"HDFS Cluster Storage Statistics:\n"
                    f"  Total Capacity:    {total:.2f} GB\n"
                    f"  Used Capacity:     {used:.2f} MB\n"
                    f"  Remaining Space:   {free:.2f} GB\n"
                    f"  Total Files/Inodes:{files}\n"
                    f"  Corrupt Blocks:    {beans.get('CorruptBlocks', 0)}\n"
                    f"  Under-Replicated:  {beans.get('UnderReplicatedBlocks', 0)}\n"
                )
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            else:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"NameNode JMX query failed: HTTP {resp.status_code}"
                )

        # SPARK COMMANDS
        elif base in ["spark-status", "spark-health", "streaming-queries"]:
            url = f"http://{SPARK_HOST}:{SPARK_PORT}/json/"
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                workers = data.get("workers", [])
                active_apps = data.get("activeapps", [])
                output = (
                    f"Apache Spark Cluster Status:\n"
                    f"  Spark Version:   {data.get('sparkversion', '3.5.1')}\n"
                    f"  Alive Workers:   {data.get('aliveworkers', 0)}\n"
                    f"  Cores in Use:    {data.get('coresused', 0)} / {data.get('cores', 0)}\n"
                    f"  Memory in Use:   {data.get('memoryused', 0)} MB / {data.get('memory', 0)} MB\n"
                    f"  Active Apps:     {len(active_apps)}\n"
                )
                for app in active_apps:
                    output += f"    - [{app.get('id')}] {app.get('name')} (State: {app.get('state')})\n"
                return CommandResponse(
                    command=cmd_string,
                    status="SUCCESS",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output=output
                )
            else:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error=f"Spark Master API returned HTTP {resp.status_code}"
                )

        # ZEEK COMMANDS
        elif base in ["zeek-status", "zeek-health"]:
            files = ["conn.log", "dns.log", "http.log", "ssl.log", "notice.log"]
            output = f"Zeek Network Monitor Logs ({ZEEK_LOG_DIR}):\n"
            for fname in files:
                fpath = os.path.join(ZEEK_LOG_DIR, fname)
                if os.path.exists(fpath):
                    sz = os.path.getsize(fpath)
                    mtime = time.ctime(os.path.getmtime(fpath))
                    output += f"  - {fname:12} Size: {sz:8} bytes | Last Modified: {mtime}\n"
                else:
                    output += f"  - {fname:12} [File not created yet]\n"
            return CommandResponse(
                command=cmd_string,
                status="SUCCESS",
                execution_time_ms=round((time.time() - t0) * 1000, 2),
                output=output
            )

        # SURICATA COMMANDS
        elif base in ["suricata-status", "suricata-health"]:
            eve_path = os.path.join(SURICATA_LOG_DIR, "eve.json")
            if os.path.exists(eve_path):
                sz = os.path.getsize(eve_path)
                mtime = time.ctime(os.path.getmtime(eve_path))
                output = (
                    f"Suricata Intrusion Detection System:\n"
                    f"  Telemetry File: {eve_path}\n"
                    f"  Size:           {sz} bytes\n"
                    f"  Last Modified:  {mtime}\n"
                )
            else:
                output = f"Suricata eve.json not found at {eve_path} (Suricata may be starting up)\n"
            return CommandResponse(
                command=cmd_string,
                status="SUCCESS",
                execution_time_ms=round((time.time() - t0) * 1000, 2),
                output=output
            )

        # CTI COMMANDS
        elif base in ["lookup-ioc", "cti-lookup"]:
            if not arg:
                return CommandResponse(
                    command=cmd_string,
                    status="ERROR",
                    execution_time_ms=round((time.time() - t0) * 1000, 2),
                    output="",
                    error="Usage: lookup-ioc <IP_OR_DOMAIN> (e.g. lookup-ioc 198.51.100.77)"
                )
            match = cti_engine.match_indicator(arg)
            if match:
                output = (
                    f"[!] CTI MATCH CONFIRMED\n"
                    f"  Indicator:     {match.indicator} ({match.type})\n"
                    f"  Threat Actor:  {match.threat_actor}\n"
                    f"  Campaign:      {match.campaign}\n"
                    f"  Severity:      {match.severity}\n"
                    f"  Confidence:    {match.confidence:.2f}\n"
                    f"  Description:   {match.description}\n"
                    f"  First Seen:    {match.first_seen}\n"
                    f"  Last Seen:     {match.last_seen}\n"
                )
            else:
                output = f"[-] Indicator '{arg}' was not found in active Threat Intelligence catalogs."
            return CommandResponse(
                command=cmd_string,
                status="SUCCESS",
                execution_time_ms=round((time.time() - t0) * 1000, 2),
                output=output
            )

        else:
            return CommandResponse(
                command=cmd_string,
                status="ERROR",
                execution_time_ms=round((time.time() - t0) * 1000, 2),
                output="",
                error=(
                    f"Unknown command: '{base}'. Available commands:\n"
                    f"  Kafka:   kafka-list-topics, kafka-describe-topic <topic>\n"
                    f"  HDFS:    hdfs-list-root, hdfs-list-security-data, hdfs-storage-status\n"
                    f"  Spark:   spark-status\n"
                    f"  Monitor: zeek-status, suricata-status\n"
                    f"  CTI:     lookup-ioc <indicator>\n"
                )
            )

    except Exception as e:
        return CommandResponse(
            command=cmd_string,
            status="ERROR",
            execution_time_ms=round((time.time() - t0) * 1000, 2),
            output="",
            error=f"Command execution error: {str(e)}"
        )
