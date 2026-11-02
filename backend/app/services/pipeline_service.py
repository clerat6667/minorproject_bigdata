"""
Big Data Pipeline & HDFS Analytics Service.
Queries genuine live metrics from:
- Apache Hadoop HDFS (NameNode JMX & WebHDFS /security-data tree)
- Apache Kafka (Cluster broker & Active topic partitions)
- Apache Spark (Master 3.5.1 cluster status, workers, streaming applications)
"""

import os
import time
import requests
from typing import Dict, Any, List

KAFKA_HOST = os.getenv("KAFKA_HOST", "kafka")
KAFKA_PORT = int(os.getenv("KAFKA_PORT", 9092))
HDFS_HOST = os.getenv("HDFS_HOST", "namenode")
HDFS_PORT = int(os.getenv("HDFS_PORT", 9870))
SPARK_HOST = os.getenv("SPARK_HOST", "spark-master")
SPARK_PORT = int(os.getenv("SPARK_PORT", 8080))

def get_hdfs_pipeline_data() -> Dict[str, Any]:
    """Retrieve genuine HDFS storage metrics and directory hierarchy."""
    result = {
        "status": "UNKNOWN",
        "total_gb": 0.0,
        "used_mb": 0.0,
        "remaining_gb": 0.0,
        "total_files": 0,
        "directories": [],
        "processed_batches": 0
    }
    # 1. Query JMX for capacity
    try:
        jmx_url = f"http://{HDFS_HOST}:{HDFS_PORT}/jmx?qry=Hadoop:service=NameNode,name=FSNamesystem"
        r = requests.get(jmx_url, timeout=2.5)
        if r.status_code == 200:
            beans = r.json().get("beans", [{}])[0]
            result["status"] = "ONLINE"
            result["total_gb"] = round(beans.get("CapacityTotal", 0) / (1024**3), 2)
            result["used_mb"] = round(beans.get("CapacityUsed", 0) / (1024**2), 2)
            result["remaining_gb"] = round(beans.get("CapacityRemaining", 0) / (1024**3), 2)
            result["total_files"] = beans.get("FilesTotal", 0)
    except Exception as e:
        result["status"] = f"OFFLINE ({str(e)})"

    # 2. Query /security-data directories
    try:
        dir_url = f"http://{HDFS_HOST}:{HDFS_PORT}/webhdfs/v1/security-data?op=LISTSTATUS"
        r = requests.get(dir_url, timeout=2.5)
        if r.status_code == 200:
            statuses = r.json().get("FileStatuses", {}).get("FileStatus", [])
            result["directories"] = [
                {
                    "path": f"/security-data/{f.get('pathSuffix')}",
                    "type": f.get("type"),
                    "length": f.get("length", 0),
                    "owner": f.get("owner", "hdfs")
                }
                for f in statuses
            ]
    except Exception:
        pass

    # 3. Query processed batches count
    try:
        batch_url = f"http://{HDFS_HOST}:{HDFS_PORT}/webhdfs/v1/security-data/processed/network-events?op=LISTSTATUS"
        r = requests.get(batch_url, timeout=2.5)
        if r.status_code == 200:
            batches = r.json().get("FileStatuses", {}).get("FileStatus", [])
            result["processed_batches"] = len(batches)
    except Exception:
        pass

    return result

def get_spark_pipeline_data() -> Dict[str, Any]:
    """Retrieve genuine Spark 3.5.1 cluster status and active streaming jobs."""
    result = {
        "status": "UNKNOWN",
        "version": "3.5.1",
        "alive_workers": 0,
        "cores_used": 0,
        "cores_total": 0,
        "memory_used_mb": 0,
        "memory_total_mb": 0,
        "active_applications": []
    }
    try:
        r = requests.get(f"http://{SPARK_HOST}:{SPARK_PORT}/json/", timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            result["status"] = "ONLINE"
            result["version"] = data.get("sparkversion", "3.5.1")
            result["alive_workers"] = data.get("aliveworkers", 0)
            result["cores_used"] = data.get("coresused", 0)
            result["cores_total"] = data.get("cores", 0)
            result["memory_used_mb"] = data.get("memoryused", 0)
            result["memory_total_mb"] = data.get("memory", 0)
            for app in data.get("activeapps", []):
                result["active_applications"].append({
                    "id": app.get("id"),
                    "name": app.get("name"),
                    "cores": app.get("cores"),
                    "memory_per_executor": app.get("memoryperslave"),
                    "state": app.get("state"),
                    "duration_sec": app.get("duration", 0) // 1000
                })
    except Exception as e:
        result["status"] = f"OFFLINE ({str(e)})"
    return result

def get_kafka_pipeline_data() -> Dict[str, Any]:
    """Retrieve active Kafka topics and cluster connectivity."""
    result = {
        "status": "UNKNOWN",
        "broker": f"{KAFKA_HOST}:{KAFKA_PORT}",
        "topics": []
    }
    try:
        from kafka import KafkaConsumer
        consumer = KafkaConsumer(
            bootstrap_servers=[f"{KAFKA_HOST}:{KAFKA_PORT}"],
            request_timeout_ms=5000,
            session_timeout_ms=4000
        )
        topics = list(consumer.topics())
        consumer.close()
        result["status"] = "ONLINE"
        result["topics"] = sorted([t for t in topics if not t.startswith("__")])
    except Exception as e:
        result["status"] = f"OFFLINE ({str(e)})"
    return result

def get_complete_pipeline_analytics() -> Dict[str, Any]:
    """Aggregate Big Data pipeline telemetry."""
    return {
        "timestamp": time.time(),
        "hdfs": get_hdfs_pipeline_data(),
        "spark": get_spark_pipeline_data(),
        "kafka": get_kafka_pipeline_data()
    }
