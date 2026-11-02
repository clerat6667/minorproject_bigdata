# Real-Time Cyber Threat Detection and Security Analytics Using Big Data

**Department of Artificial Intelligence and Data Science**  
**University College of Engineering Thodupuzha**
**team members:devanandhana pramod (project lead),  Ardhra k Joy , Clerat O S , Aswajith C A , Akshay Krishna** 

---

## 1. Project Overview

This project is a production-grade, genuine Big Data cybersecurity analytics platform designed for real-time network security monitoring, threat detection, anomaly classification, and incident correlation.

Unlike theoretical or mock systems that generate artificial JSON packets in Python loops, this platform enforces a **strict, non-negotiable real-world pipeline**:
- **Real network traffic** traverses the test lab.
- **Zeek (v6.0)** and **Suricata IDS (v8.0)** sniff network interfaces and generate structured security telemetry (`conn.log`, `dns.log`, `http.log`, `notice.log`, `eve.json`).
- **Apache Kafka (v3.7.1 in KRaft mode)** acts as the real-time event streaming backbone.
- **Apache Spark Structured Streaming (v3.5.1)** with **Spark SQL** and **Spark MLlib** consumes live Kafka streams, computes sliding-window behavioral features, detects statistical/rule-based anomalies, and classifies threats with evidence-based confidence.
- **Apache Hadoop HDFS (v3.2.1)** stores raw and processed telemetry as an immutable historical Big Data lake.
- **Cyber Threat Intelligence (CTI)** correlates observed indicators against MISP / OpenCTI-compatible feeds.
- **FastAPI Backend & WebSocket Broadcaster** feeds a reactive **Cybersecurity SOC Dashboard** and an **Interactive Command Center** terminal with real-time operational diagnostics.

> **Non-Negotiable Principle**:  
> **REAL TRAFFIC → REAL MONITORING → REAL KAFKA → REAL SPARK → REAL DETECTION → REAL CTI CORRELATION → REAL HDFS STORAGE → REAL ALERT → REAL DASHBOARD**  
> If any service is stopped, the platform reports genuine `OFFLINE` status and exact connection errors—never simulated successes.

---

## 2. End-to-End System Architecture

```text
                    ┌─────────────────────────────────────────┐
                    │           Controlled Test Lab           │
                    │  Kali Linux / Scapy / Normal Browsing   │
                    │     Target: OWASP Juice Shop (v20.2)    │
                    └────────────────────┬────────────────────┘
                                         │
                                 REAL NETWORK TRAFFIC
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │        Network Monitoring Layer         │
                    │                                         │
                    │  Zeek (conn, dns, http, ssl, notice)    │
                    │  Suricata (eve.json alerts, flows)      │
                    └────────────────────┬────────────────────┘
                                         │
                                Structured Logs
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │        Telemetry Log Shippers           │
                    │  Python real-time watchers & producers  │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │              Apache Kafka               │
                    │  Topics: network-events, zeek-events,   │
                    │  suricata-events, suricata-alerts,      │
                    │  dns-events, http-events, threat-alerts │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │       Apache Spark 3.5.1 Cluster        │
                    │         Structured Streaming            │
                    │                                         │
                    │  • Sliding Windows (5s, 10s, 30s, 1m)   │
                    │  • Spark SQL Feature Aggregations       │
                    │  • Spark MLlib Anomaly Scoring          │
                    │  • Multi-Engine Threat Classification   │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
       ┌───────────────────────────┐             ┌───────────────────────────┐
       │   Apache Hadoop HDFS      │             │    Kafka Alert Stream     │
       │   Historical Security Lake│             │    Topic: threat-alerts   │
       │   /security-data/raw/     │             └─────────────┬─────────────┘
       │   /security-data/processed│                           │
       │   /security-data/alerts/  │                           ▼
       └───────────────────────────┘             ┌───────────────────────────┐
                                                 │      FastAPI Backend      │
                                                 │  • Kafka Consumer Service │
                                                 │  • CTI Engine (MISP/O-CTI)│
                                                 │  • Incident Correlator    │
                                                 │  • Real Health Probers    │
                                                 │  • Command Diagnostics    │
                                                 └─────────────┬─────────────┘
                                                               │
                                                 ┌─────────────┴─────────────┐
                                                 ▼                           ▼
                                      WebSocket (/ws/stream)            REST APIs
                                                 ▼                           ▼
                                      ┌──────────────────────────────────────────┐
                                      │        Security SOC Web Dashboard        │
                                      │  • Real-Time Live Telemetry Stream       │
                                      │  • Threat Alerts & Incident Explorer     │
                                      │  • Protocol & Anomaly Visual Analytics   │
                                      │  • Threat Intelligence Feed (CTI)        │
                                      │  • Live Infrastructure Health Matrix     │
                                      │  • Interactive Diagnostic Command Center │
                                      └──────────────────────────────────────────┘
```

---

## 3. Technologies & Versions

| Component | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Stream Backbone** | Apache Kafka | 3.7.1 (KRaft) | High-throughput distributed event streaming |
| **Data Lake** | Apache Hadoop HDFS | 3.2.1 | Distributed raw & processed historical data storage |
| **Big Data Engine** | Apache Spark | 3.5.1 | Real-time Structured Streaming & SQL window aggregations |
| **Machine Learning**| Spark MLlib | 3.5.1 | Statistical baseline modeling & anomaly scoring |
| **NSM Engine** | Zeek | 6.0.4 | Deep protocol parsing & structured JSON connection telemetry |
| **NIDS Engine** | Suricata | 8.0.7 | Signature-based network intrusion detection (`eve.json`) |
| **Target App** | OWASP Juice Shop | 20.2.0 | Intentionally vulnerable application for authorized security testing |
| **Backend API** | FastAPI | 0.142.2 | REST endpoints, WebSockets, incident correlation, health probers |
| **Frontend** | HTML5 / Tailwind / Chart.js | Modern SOC | Real-time reactive dashboard and terminal command center |
| **Packet Generator**| Scapy / Python Sockets | 3.11+ | Controlled network anomaly and attack scenario generation |
| **CTI Layer** | MISP / OpenCTI Model | Custom Engine | Real-time threat actor, campaign, and IOC correlation |

---

## 4. Prerequisites

- **Operating System**: Windows 10/11 (with WSL2 enabled) or Ubuntu Linux.
- **Docker Desktop**: Docker Engine v24+ and Docker Compose v2.20+.
- **Memory Allocation**: Minimum 8 GB RAM (WSL2 / Docker Desktop configured with at least 6-8 GB).
- **Python**: Python 3.10+ (for local attack scenarios and scripts).

---

## 5. Directory Structure

```text
cyber-threat-detection/
├── docker-compose.yml              # Cluster topology (Kafka, HDFS, Spark, Zeek, Suricata, Juice Shop, Backend)
├── README.md                       # Comprehensive system documentation
├── DEMO_GUIDE.md                   # Live demonstration walkthrough guide
├── system_architecture_design.md   # System architecture specification
│
├── infrastructure/
│   ├── kafka/
│   │   └── create_topics.sh        # Automates creation of all 9 cybersecurity topics
│   ├── hadoop/
│   │   └── init_hdfs.sh            # Initializes /security-data data lake directories
│   ├── zeek/
│   │   └── local.zeek              # Zeek local policy enabling JSON logging & scan detection
│   └── suricata/
│       ├── suricata.yaml           # Suricata configuration for live eth0 packet capture
│       └── local.rules             # Custom IDS detection rules (recon, brute force, DoS, CTI)
│
├── network_monitoring/
│   ├── zeek_shipper.py             # Tails conn.log, dns.log, http.log into Kafka & HDFS
│   ├── suricata_shipper.py         # Tails eve.json alerts and flows into Kafka & HDFS
│   └── raw_packet_bridge.py        # Scapy live packet capture helper
│
├── streaming/
│   ├── spark_streaming_job.py      # Apache Spark Structured Streaming detection application
│   └── schemas.py                  # PySpark StructType schemas for network events and alerts
│
├── backend/
│   ├── requirements.txt            # Python dependencies (fastapi, uvicorn, kafka-python-ng, etc.)
│   ├── Dockerfile                  # Container definition for backend service
│   └── app/
│       ├── main.py                 # FastAPI application and WebSocket router
│       ├── models.py               # Pydantic schemas (Event, Alert, Incident, Health, Command)
│       ├── static/
│       │   └── index.html          # Reactive SOC Dashboard & Terminal Command Center
│       └── services/
│           ├── health_checker.py   # True socket & HTTP probers for Kafka, HDFS, Spark, Zeek, etc.
│           ├── command_executor.py # Genuine diagnostic command executor for Command Center
│           ├── cti_engine.py       # MISP/OpenCTI threat intelligence catalog and matcher
│           ├── incident_correlator.py # False-positive reducer and multi-alert incident clustering
│           └── kafka_consumer_service.py # Kafka consumer loop and WebSocket streaming dispatcher
│
└── attack_lab/
    ├── attack_runner.py            # CLI scenario orchestrator
    └── scenarios/
        ├── normal_traffic.py       # Baseline legitimate HTTP browsing and API lookups
        ├── port_scan.py            # Controlled reconnaissance scan across 24 TCP ports
        ├── brute_force.py          # Credential stuffing against Juice Shop /rest/user/login
        ├── http_burst.py           # High-rate HTTP DoS-like request burst
        ├── dns_anomaly.py          # High-entropy DNS tunneling lookups & NXDOMAIN bursts
        └── ioc_test.py             # Connection probes targeting configured CTI threat actor IP
```

---

## 6. Installation & Quick Start

### Step 1: Start Core Infrastructure

Launch Apache Kafka, Hadoop HDFS, and the cluster initialization containers:
```bash
docker compose up -d kafka namenode datanode
```

Verify that Kafka and HDFS NameNode are healthy:
```bash
docker compose ps
```

### Step 2: Initialize Topics and HDFS Directories

Run the initialization jobs:
```bash
docker compose up kafka-init hdfs-init
```
This automatically creates:
- **Kafka Topics**: `network-events`, `zeek-events`, `suricata-events`, `suricata-alerts`, `dns-events`, `http-events`, `anomaly-events`, `threat-alerts`, `correlated-incidents`.
- **HDFS Directories**:
  ```text
  /security-data/
  ├── raw/ (zeek, suricata)
  ├── processed/ (network-events, dns, http)
  ├── alerts/
  ├── anomalies/
  ├── threat-intelligence/
  └── checkpoints/spark/
  ```

### Step 3: Launch Spark, Monitoring & Target Services

Start the remaining services:
```bash
docker compose up -d spark-master spark-worker juice-shop zeek suricata telemetry-shipper backend
```

Verify that all 10 containers are running:
```bash
docker compose ps
```

### Step 4: Submit Spark Structured Streaming Job

Submit the streaming detection job into the Spark cluster:
```bash
docker exec -d cyber-spark-master /opt/spark/bin/spark-submit \
  --master spark://spark-master:7077 \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
  --exclude-packages org.apache.hadoop:hadoop-client-runtime,org.apache.hadoop:hadoop-client-api \
  --conf spark.driver.host=spark-master \
  --conf spark.pyspark.python=python3 \
  /opt/streaming/spark_streaming_job.py
```

Verify the active streaming job via Spark Master:
```bash
curl http://localhost:8080/json/
```
Output will confirm: `"name": "RealTimeCyberThreatDetection", "state": "RUNNING"`.

---

## 7. Accessing the Platform

| Interface | URL | Purpose |
| :--- | :--- | :--- |
| **Security SOC Dashboard** | `http://localhost:8000/` | Live event stream, threat alerts, incidents, health, command center |
| **Backend REST API Docs** | `http://localhost:8000/docs` | OpenAPI interactive documentation |
| **WebSocket Stream** | `ws://localhost:8000/ws/stream` | Sub-second real-time streaming endpoint |
| **HDFS NameNode Web UI** | `http://localhost:9870/` | Hadoop file system browser, storage quotas, block health |
| **Apache Spark Master UI** | `http://localhost:8080/` | Active workers, streaming queries, executor memory |
| **OWASP Juice Shop** | `http://localhost:3000/` | Authorized vulnerable target web application |
| **Kafka Broker** | `localhost:9092` / `localhost:29092` | Event streaming broker |

---

## 8. Threat Detection Methodology

The detection engine uses a **multi-layered, hybrid evaluation pipeline**:

### 1. Sliding Window Feature Extraction (Spark SQL)
PySpark Structured Streaming computes micro-batch aggregations across sliding time windows (10-second windows with 5-second slides):
- `unique_destination_ports`: Variance and entropy of targeted ports per source IP.
- `failed_auth_count`: Sum of HTTP 401 Unauthorized status codes per source IP.
- `request_rate`: Request frequency directed at web endpoints.
- `dns_query_count`: DNS lookups and NXDOMAIN frequency.
- `byte_ratio`: Ratio of `bytes_sent` to `bytes_received`.

### 2. Multi-Engine Anomaly Detection
- **Rule-Based Engine**: Identifies threshold crossings for high-variance scanning (`unique_ports >= 10`), brute force (`failed_logins >= 4`), and request floods (`http_requests >= 20`).
- **Statistical Z-Score Engine**: Computes rolling means and standard deviations; flags activity exceeding $3.5\sigma$ from normal baseline.
- **Spark MLlib Engine**: Utilizes VectorAssemblers and distance-based clustering to detect multi-dimensional behavioral outliers.

### 3. Classification & Evidence Reasoning
Detected threats are classified into standardized categories:
- `NORMAL`
- `PORT_SCAN`
- `BRUTE_FORCE`
- `DOS_LIKE`
- `DNS_ANOMALY`
- `SUSPICIOUS_CONNECTION`
- `IDS_SIGNATURE_MATCH`

Every alert includes calculated confidence and concrete evidence:
```json
{
  "alert_id": "alt-4819a0e1",
  "timestamp": "2026-10-06T17:46:10.123Z",
  "source_ip": "172.28.0.1",
  "destination_ip": "172.28.0.20",
  "threat_type": "PORT_SCAN",
  "severity": "HIGH",
  "confidence": 0.94,
  "detection_method": "SPARK_SQL_WINDOW_ENTROPY",
  "evidence": [
    "24 unique destination ports probed in micro-batch window",
    "Source IP 172.28.0.1 targeted 172.28.0.20 across high port variance"
  ],
  "ioc_match": false
}
```

---

## 9. Cyber Threat Intelligence (CTI) & IOC Correlation

The CTI layer matches observed telemetry against curated threat intelligence feeds (MISP & OpenCTI compatible format).

The platform strictly differentiates:
1. **Behavioral Anomaly**: Source IP exhibits anomalous connection rates or port entropy.
2. **IDS Signature Match**: Suricata rule matches a specific pattern (e.g., Nmap SYN scan).
3. **Known Malicious IOC Match**: Source or destination IP is present in configured threat intelligence catalogs (e.g., APT-29 C2 node `198.51.100.77`).

When an IOC match occurs:
- The alert severity is escalated to `CRITICAL`.
- Confidence is set to $\ge 0.98$.
- Evidence cites the specific threat actor, campaign, and first/last seen timestamps.

---

## 10. False Positive Reduction & Incident Correlation

To prevent alert fatigue and false positives:
1. **Baseline Filtering**: Single unusual connections do not trigger critical alerts.
2. **Multi-Event Correlation**: Individual alerts matching the same source IP within a sliding timeframe are grouped into a unified **Incident Object** (e.g., `INC-20261006-XXXXXX`).
3. **Temporal Cooldown**: Duplicate alerts for the same source within 30 seconds are suppressed and increment the incident's alert count.
4. **Severity Escalation**: An incident with both reconnaissance (`PORT_SCAN`) and exploitation (`BRUTE_FORCE`) is automatically escalated to `CRITICAL`.

---

## 11. Cyber Range Attack Initiator & Port Allocations

The platform features two complementary interfaces:
1. **Blue Team SOC Dashboard (`http://localhost:8000/`)**:
   - Real-time telemetry feed (Zeek & Suricata)
   - Real-time threat alerts & correlated incidents
   - **Big Data Pipeline & HDFS View**: Live NameNode capacity, `/security-data` tree, Spark micro-batches, and Kafka broker topics.
   - Anomaly analytics & CTI catalog
2. **Red Team Cyber Range Attack Simulator (`http://localhost:8050/`)**:
   - Dedicated attack generator UI running on a separate port.
   - 1-click execution for TCP port scans, UDP bursts, brute force, IDOR, SQLi, HTTP floods, and DNS tunneling.
   - Live stdout streaming terminal.
   - Automated "Launch Full Campaign" master execution.

### Service Port Map

| Port | Service | Purpose |
| :--- | :--- | :--- |
| **8000** | Blue Team SOC Dashboard | Real-time security analytics & event streams |
| **8050** | Red Team Cyber Range UI | Attack initiation & traffic generation console |
| **3000** | OWASP Juice Shop | Target lab environment for authorized testing |
| **8080** | Apache Spark Master UI | Cluster worker metrics and streaming job status |
| **9870** | Hadoop NameNode WebHDFS | Distributed storage browser (`/security-data`) |
| **9092** | Apache Kafka Broker | Distributed messaging backbone (KRaft) |

---

## 12. Controlled Attack Lab Scenarios

Run controlled tests using the provided test runner:

```bash
# 1. Generate legitimate baseline browsing
python attack_lab/attack_runner.py --scenario normal

# 2. Controlled port scan across 24 TCP ports
python attack_lab/attack_runner.py --scenario port_scan

# 3. Repeated failed authentication against Juice Shop
python attack_lab/attack_runner.py --scenario brute_force

# 4. High-rate HTTP burst (DoS pattern)
python attack_lab/attack_runner.py --scenario http_burst

# 5. High-entropy DNS tunneling lookups
python attack_lab/attack_runner.py --scenario dns_anomaly

# 6. Test flagged CTI indicator (APT-29 IP 198.51.100.77)
python attack_lab/attack_runner.py --scenario ioc_test

# 7. Run all scenarios in sequence
python attack_lab/attack_runner.py --scenario all
```

---

## 13. System Health Monitoring

The health checker queries live endpoints every 5 seconds. If a component stops:
- **Kafka stopped**: Reports `OFFLINE: Connection refused by kafka:9092`.
- **HDFS stopped**: Reports `OFFLINE: NameNode unreachable`.
- **Spark stopped**: Reports `OFFLINE: Spark Master unreachable`.
- **Zeek idle**: Reports `DEGRADED: conn.log idle for >180s`.

The dashboard status reflects the true state of the backend.

---

## 14. Testing & Verification

Run health checks via PowerShell:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/health" | Format-Table name, status, latency_ms, details, error -AutoSize
```

Query live statistics:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/stats"
```

Verify HDFS storage via WebHDFS:
```powershell
Invoke-RestMethod -Uri "http://localhost:9870/webhdfs/v1/security-data?op=LISTSTATUS" | Select-Object -ExpandProperty FileStatuses
```

---

## 15. Security Research Notice

This software is developed strictly for **educational and defensive cybersecurity research** within an isolated laboratory environment. All attack scenarios are rate-limited and restricted to target systems owned or explicitly authorized by the operator (`localhost`, `172.28.0.0/16`, OWASP Juice Shop). Never target unauthorized or public systems.
#   m i n o r p r o j e c t _ b i g d a t a  
 