import io
from datetime import datetime

def generate_formal_audit_text(
    stats: dict,
    incidents: list,
    alerts: list,
    events: list,
    pipeline: dict
) -> io.BytesIO:
    output = []
    output.append("="*80)
    output.append(f"FORMAL CYBERSECURITY AUDIT REPORT")
    output.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    output.append("="*80)
    output.append("")
    
    output.append("1. EXECUTIVE SUMMARY")
    output.append("-" * 30)
    output.append(f"Total Network Events: {stats.get('total_events', 0)}")
    output.append(f"Active Threat Alerts: {stats.get('active_alerts', 0)}")
    output.append(f"Critical Severity Threats: {stats.get('critical_alerts', 0)}")
    output.append(f"Correlated Incidents: {len(incidents)}")
    output.append(f"ML Anomalies Detected: {stats.get('anomalies_detected', 0)}")
    output.append(f"CTI Indicator Matches: {stats.get('ioc_matches', 0)}")
    output.append("")

    output.append("2. CORRELATED INCIDENT LOG")
    output.append("-" * 30)
    if not incidents:
        output.append("No active incidents.")
    for inc in incidents:
        output.append(f"Incident ID: {inc.get('incident_id')}")
        output.append(f"Severity: {inc.get('severity')} | Status: {inc.get('status')}")
        output.append(f"Threats: {', '.join(inc.get('threat_types', []))}")
        output.append(f"Source IP(s): {', '.join(inc.get('source_ips', []))}")
        output.append(f"Target IP(s): {', '.join(inc.get('destination_ips', []))}")
        output.append("Evidence:")
        for ev in inc.get('evidence', []):
            output.append(f"  - {ev}")
        output.append("")

    output.append("3. DETAILED THREAT ALERTS (LATEST)")
    output.append("-" * 30)
    if not alerts:
        output.append("No active alerts.")
    for alt in alerts:
        output.append(f"[{alt.get('timestamp')}] {alt.get('severity')} - {alt.get('threat_type')}")
        output.append(f"Source: {alt.get('source_ip')} -> Destination: {alt.get('destination_ip')}")
        output.append(f"Detection Method: {alt.get('detection_method')} (Confidence: {int(alt.get('confidence', 0)*100)}%)")
        output.append("")

    output.append("4. INFRASTRUCTURE & PIPELINE STATUS")
    output.append("-" * 30)
    kafka = pipeline.get("kafka", {})
    output.append(f"Kafka Broker: {kafka.get('status', 'UNKNOWN')} | Topics: {len(kafka.get('topics', []))}")
    spark = pipeline.get("spark", {})
    output.append(f"Spark Engine: {spark.get('status', 'UNKNOWN')} | Cores Used: {spark.get('cores_used', 0)}")
    hdfs = pipeline.get("hdfs", {})
    output.append(f"HDFS Storage: {hdfs.get('status', 'UNKNOWN')} | Used: {hdfs.get('used_mb', 0)}MB")
    output.append("")
    
    output.append("="*80)
    output.append("END OF REPORT")
    output.append("="*80)
    
    return io.BytesIO("\n".join(output).encode('utf-8'))
