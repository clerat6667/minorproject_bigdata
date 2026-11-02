# Live Demonstration & Presentation Guide

**Real-Time Cyber Threat Detection and Security Analytics Using Big Data**  
Department of Artificial Intelligence and Data Science, University College of Engineering Thodupuzha

---

## Demonstration Overview

This guide walks an evaluator or presenter through a complete, live demonstration of the Big Data cybersecurity pipeline. Every action executed here generates real network packets, which are processed live through:
```text
Real Network Traffic ──> Zeek / Suricata ──> Apache Kafka ──> Spark Structured Streaming ──> Detection / ML ──> CTI Matching ──> HDFS Storage ──> Live Dashboard
```

---

## Two-Console Live Architecture
During presentations or evaluations, use a dual-tab or split-screen setup:
1. **Red Team Cyber Range Attack Initiator**: `http://localhost:8050/`
   - Interactive UI to trigger port scans, brute force, IDOR, SQLi, HTTP floods, UDP bursts, and DNS anomalies with a single click.
2. **Blue Team SOC Real-Time Analytics Dashboard**: `http://localhost:8000/`
   - Real-time event cards, IDS alerts, correlated incident clusters, HDFS storage metrics, and Big Data streaming analytics.

---

## Pre-Flight Checklist

1. Open your browser to the **SOC Dashboard**:
   ```
   http://localhost:8000/
   ```
2. Open the **Cyber Range Attack Simulator**:
   ```
   http://localhost:8050/
   ```
   *(Or double-click `start_attack_ui.bat`)*
3. Verify that the **Cluster Infrastructure Quick Bar** at the top of the SOC shows green/online status for:
   - `Kafka` (Broker active on port 9092)
   - `HDFS` (NameNode WebHDFS active on port 9870)
   - `Spark` (Master active on port 8080 with live worker)
   - `Zeek` (Network monitor sniffing eth0)
   - `Suricata` (IDS engine sniffing eth0)
   - `CTI` (Curated threat intelligence indicators loaded)
4. In another browser tab, open the **Spark Master UI**:
   ```
   http://localhost:8080/
   ```
   Confirm that `RealTimeCyberThreatDetection` is in the `RUNNING` state.
5. In another browser tab, open the **HDFS NameNode UI**:
   ```
   http://localhost:9870/
   ```
   Navigate to **Utilities** → **Browse the file system** → `/security-data`.

---

## Demonstration Steps

### Step 1: Baseline Normal Traffic

**Goal**: Demonstrate that the system does not produce false alerts during normal, legitimate traffic.

**Execution**:
Run the normal browsing script in a terminal:
```bash
python attack_lab/attack_runner.py --scenario normal
```

**Expected Observation**:
- **Terminal**: Outputs 15 successful HTTP requests against Juice Shop (`/`, `/api/Products`, `/rest/admin/...`).
- **Dashboard Overview**:
  - `Total Events` increments by 15.
  - `Throughput (evt/sec)` spikes to reflect traffic.
  - `Protocol Distribution` shows normal HTTP and TCP traffic.
- **Alerts Table**: **Zero new alerts generated** (confirming baseline noise suppression).

---

### Step 2: Controlled Port Scan Anomaly

**Goal**: Demonstrate real-time reconnaissance detection via Spark SQL sliding-window port entropy.

**Execution**:
Run the port scan scenario:
```bash
python attack_lab/attack_runner.py --scenario port_scan
```

**Expected Observation**:
- **Terminal**: Scans 24 TCP ports across a short time interval.
- **Zeek & Suricata**: Observe multiple connection attempts from the same source IP.
- **Spark Structured Streaming**: Window aggregation detects `unique_destination_ports >= 10`.
- **Dashboard Live Stream**:
  - A new alert appears in the **Threat Alerts** section:
    - **Threat Type**: `PORT_SCAN`
    - **Severity**: `HIGH`
    - **Confidence**: `0.94`
    - **Evidence**: `24 unique destination ports probed in micro-batch window`
- **HDFS**: The alert is automatically stored in `/security-data/alerts/`.

---

### Step 3: Authentication Attack Pattern (Brute Force)

**Goal**: Detect rapid credential stuffing against the target web application.

**Execution**:
Run the brute force scenario:
```bash
python attack_lab/attack_runner.py --scenario brute_force
```

**Expected Observation**:
- **Terminal**: Submits 8 rapid failed login requests to Juice Shop (`/rest/user/login`), resulting in HTTP 401 Unauthorized responses.
- **Zeek**: Logs HTTP 401 response codes in `http.log`.
- **Suricata**: Triggers rule `1000002` ("Juice Shop Brute Force Attempt").
- **Spark Streaming**: Detects `failed_logins >= 4` in the micro-batch window.
- **Dashboard**:
  - **Threat Alert**: `BRUTE_FORCE` (Severity: `HIGH`, Confidence: `0.92`).
  - **Correlated Incident**: Automatically clusters the port scan and brute force from the same source IP into a unified **Incident Object** (Severity escalated to `CRITICAL`).

---

### Step 4: High-Rate HTTP Request Burst (DoS-like Behavior)

**Goal**: Demonstrate statistical anomaly detection during high request rates.

**Execution**:
Run the HTTP request burst scenario:
```bash
python attack_lab/attack_runner.py --scenario http_burst
```

**Expected Observation**:
- **Terminal**: Sends 40 multi-threaded HTTP requests in under 2 seconds (~25 req/sec).
- **Spark Streaming**: Request rate exceeds the $4.0\sigma$ baseline threshold.
- **Dashboard**:
  - **Threat Alert**: `DOS_LIKE` (Severity: `CRITICAL`).
  - **Evidence**: `High HTTP request burst: 40 requests within window (rate exceeded normal traffic baseline)`.

---

### Step 5: Suspicious DNS Anomaly (Tunneling / Exfiltration Probe)

**Goal**: Detect high-entropy DNS query patterns and NXDOMAIN bursts.

**Execution**:
Run the DNS anomaly scenario:
```bash
python attack_lab/attack_runner.py --scenario dns_anomaly
```

**Expected Observation**:
- **Terminal**: Sends 20 rapid lookups for high-entropy random subdomains (`*.tunnel-test.local`).
- **Zeek**: Emits queries and NXDOMAIN records in `dns.log`.
- **Spark Streaming**: Window aggregation flags `dns_queries >= 12`.
- **Dashboard**:
  - **Threat Alert**: `DNS_ANOMALY` (Severity: `MEDIUM`, Confidence: `0.86`).
  - **Evidence**: `Abnormal DNS query frequency: 20 lookups in window`.

---

### Step 6: Known Threat Intelligence (CTI / IOC) Match

**Goal**: Demonstrate CTI indicator correlation and distinguish behavioral anomalies from known threat actor matches.

**Execution**:
Run the IOC test scenario:
```bash
python attack_lab/attack_runner.py --scenario ioc_test
```

**Expected Observation**:
- **Terminal**: Emits traffic directed at APT-29 C2 IP (`198.51.100.77`) and queries domain (`malware-threat-lab.local`).
- **CTI Engine**: Performs instant lookup against the MISP/OpenCTI catalog.
- **Dashboard**:
  - **Threat Alert**: Flagged with **[CTI MATCH]**.
  - **Severity**: Escalated immediately to `CRITICAL` (Confidence: `0.98`).
  - **Evidence**: `Known Threat Actor 'APT-29 (Cozy Bear)' (Operation RedCloud)`.
  - `CTI Matches` KPI counter on the overview bar increments.

---

### Step 7: Interactive Command Center Diagnostics

**Goal**: Prove to evaluators that the dashboard communicates with real infrastructure rather than displaying mock data.

**Execution**:
1. Click on the **Command Center** tab in the dashboard.
2. In the preset buttons at the top, click **`kafka-list-topics`** and press **EXECUTE**.
   - Output shows the 9 live Kafka topics on the broker.
3. Click **`hdfs-list-security-data`** and press **EXECUTE**.
   - Output displays the real directory tree from NameNode WebHDFS (`/security-data/alerts`, `/security-data/processed`, etc.).
4. Click **`spark-status`** and press **EXECUTE**.
   - Output displays Spark version `3.5.1`, live worker count, and active running applications.
5. In the input box, type:
   ```text
   lookup-ioc 198.51.100.77
   ```
   and press **EXECUTE**.
   - Output displays the full CTI dossier for APT-29.

---

### Step 8: Verifying Historical HDFS Persistence

**Goal**: Prove that alerts and processed telemetry are written to Apache Hadoop HDFS.

**Execution**:
In your terminal, execute:
```bash
docker exec cyber-hdfs-namenode hdfs dfs -ls -R /security-data/alerts
```

**Expected Observation**:
NameNode lists stored batch partitions (e.g., `/security-data/alerts/batch_0/...`), proving that historical storage in HDFS has taken place.
