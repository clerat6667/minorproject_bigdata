"""
Executive Security Statement & Excel Audit Exporter.
Generates genuine multi-sheet formatted .xlsx workbooks containing:
- Executive Summary & Security Statement
- Active Correlated Incidents
- Real-Time Threat Alerts & Classifications
- Network Event Telemetry (Protocols & Endpoints)
- CTI Threat Intelligence Matches
- Power BI Flattened Analytics Schema
"""

import io
import time
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def generate_security_statement_excel(
    stats: dict,
    incidents: list,
    alerts: list,
    events: list,
    cti_indicators: list,
    pipeline: dict
) -> io.BytesIO:
    wb = Workbook()
    
    # Define Brand Styles (Dark SOC Theme)
    title_font = Font(name="Arial", size=16, bold=True, color="FFFFFF")
    section_font = Font(name="Arial", size=12, bold=True, color="1E293B")
    header_font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
    regular_font = Font(name="Arial", size=10, color="0F172A")
    kpi_num_font = Font(name="Arial", size=14, bold=True, color="0284C7")
    kpi_label_font = Font(name="Arial", size=9, bold=False, color="64748B")
    
    header_fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    accent_fill = PatternFill(start_color="0284C7", end_color="0284C7", fill_type="solid")
    kpi_box_fill = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")
    critical_fill = PatternFill(start_color="FFE4E6", end_color="FFE4E6", fill_type="solid")
    high_fill = PatternFill(start_color="FFEDD5", end_color="FFEDD5", fill_type="solid")
    
    thin_border = Border(
        left=Side(style='thin', color='E2E8F0'),
        right=Side(style='thin', color='E2E8F0'),
        top=Side(style='thin', color='E2E8F0'),
        bottom=Side(style='thin', color='E2E8F0')
    )

    # =========================================================================
    # SHEET 1: EXECUTIVE SECURITY STATEMENT
    # =========================================================================
    ws1 = wb.active
    ws1.title = "Executive Statement"
    ws1.views.sheetView[0].showGridLines = True
    
    # Title Block
    ws1.merge_cells("A1:G2")
    ws1["A1"] = "CYBERSECURITY INCIDENT & THREAT AUDIT STATEMENT"
    ws1["A1"].font = title_font
    ws1["A1"].fill = header_fill
    ws1["A1"].alignment = Alignment(horizontal="center", vertical="center")
    
    # Subtitle
    ws1["A3"] = f"Department of AI & Data Science • Platform Audit Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    ws1["A3"].font = Font(size=9, italic=True, color="64748B")
    
    # KPI Summary Cards (Row 5 - 7)
    kpis = [
        ("Total Events", stats.get("total_events", 0)),
        ("Active Alerts", stats.get("active_alerts", 0)),
        ("Critical Threats", stats.get("critical_alerts", 0)),
        ("Open Incidents", len(incidents)),
        ("ML Anomalies", stats.get("anomalies_detected", 0)),
        ("CTI Matches", stats.get("ioc_matches", 0)),
        ("HDFS Batches", pipeline.get("hdfs", {}).get("processed_batches", 0))
    ]
    
    for idx, (label, val) in enumerate(kpis):
        col = idx + 1
        c_label = ws1.cell(row=5, column=col, value=label)
        c_label.font = kpi_label_font
        c_label.fill = kpi_box_fill
        c_label.alignment = Alignment(horizontal="center")
        c_label.border = thin_border
        
        c_val = ws1.cell(row=6, column=col, value=val)
        c_val.font = kpi_num_font
        c_val.fill = kpi_box_fill
        c_val.alignment = Alignment(horizontal="center")
        c_val.border = thin_border

    # Statement Narrative
    ws1.cell(row=9, column=1, value="1. AUDIT SUMMARY STATEMENT").font = section_font
    narrative = (
        "This security audit statement reflects real-time telemetry captured by network sensors (Zeek & Suricata), "
        "streamed through Apache Kafka, analyzed via Apache Spark Structured Streaming sliding windows, "
        "and persisted to the Apache Hadoop HDFS distributed data lake. Threat intelligence matching against "
        "MISP and OpenCTI repositories was performed concurrently with multi-source incident clustering."
    )
    ws1.merge_cells("A10:G12")
    c_nar = ws1["A10"]
    c_nar.value = narrative
    c_nar.font = regular_font
    c_nar.alignment = Alignment(wrap_text=True, vertical="top")

    # Infrastructure Status Table
    ws1.cell(row=14, column=1, value="2. BIG DATA INFRASTRUCTURE HEALTH").font = section_font
    infra_headers = ["Layer", "Technology", "Status", "Capacity / Metrics", "Details"]
    for c_idx, h in enumerate(infra_headers, start=1):
        cell = ws1.cell(row=15, column=c_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        
    infra_rows = [
        ("Message Backbone", "Apache Kafka 3.7.1", pipeline.get("kafka", {}).get("status", "ONLINE"), f"{len(pipeline.get('kafka', {}).get('topics', []))} Active Topics", "KRaft Ingestion Bus"),
        ("Stream Processing", "Apache Spark 3.5.1", pipeline.get("spark", {}).get("status", "ONLINE"), f"{pipeline.get('spark', {}).get('cores_used', 12)} Cores / {pipeline.get('spark', {}).get('memory_used_mb', 1024)} MB", "Real-Time Sliding Windows & MLlib"),
        ("Distributed Lake", "Hadoop HDFS 3.2.1", pipeline.get("hdfs", {}).get("status", "ONLINE"), f"{pipeline.get('hdfs', {}).get('total_gb', 0)} GB Total / {pipeline.get('hdfs', {}).get('processed_batches', 0)} Batches", "WebHDFS Persistence"),
        ("Network Sensor", "Zeek NSM 6.0", "ONLINE", "JSON Conn & HTTP Logs", "Deep Protocol Telemetry"),
        ("Intrusion Detection", "Suricata IDS 8.0", "ONLINE", "8 Custom Alert Signatures", "Rule-Based Packet Inspection")
    ]
    for r_idx, r_data in enumerate(infra_rows, start=16):
        for c_idx, val in enumerate(r_data, start=1):
            cell = ws1.cell(row=r_idx, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border

    # =========================================================================
    # SHEET 2: SECURITY INCIDENTS
    # =========================================================================
    ws2 = wb.create_sheet(title="Correlated Incidents")
    ws2.views.sheetView[0].showGridLines = True
    
    inc_headers = ["Incident ID", "Severity", "Status", "Confidence", "Alert Count", "Source IPs", "Destination IPs", "Threat Types", "Forensic Evidence", "First Seen", "Last Seen"]
    for c_idx, h in enumerate(inc_headers, start=1):
        cell = ws2.cell(row=1, column=c_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        
    for r_idx, inc in enumerate(incidents, start=2):
        row_data = [
            inc.get("incident_id"),
            inc.get("severity"),
            inc.get("status"),
            f"{int(inc.get('confidence', 0) * 100)}%",
            inc.get("alert_count", 0),
            ", ".join(inc.get("source_ips", [])),
            ", ".join(inc.get("destination_ips", [])),
            ", ".join(inc.get("threat_types", [])),
            "; ".join(inc.get("evidence", [])),
            inc.get("first_seen"),
            inc.get("last_seen")
        ]
        for c_idx, val in enumerate(row_data, start=1):
            cell = ws2.cell(row=r_idx, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border
            if c_idx == 2 and val == "CRITICAL":
                cell.fill = critical_fill
            elif c_idx == 2 and val == "HIGH":
                cell.fill = high_fill

    # =========================================================================
    # SHEET 3: THREAT ALERTS
    # =========================================================================
    ws3 = wb.create_sheet(title="Threat Alerts")
    ws3.views.sheetView[0].showGridLines = True
    
    alt_headers = ["Alert ID", "Timestamp", "Threat Type", "Severity", "Confidence", "Source IP", "Destination IP", "Detection Engine", "Incident ID", "Evidence Details"]
    for c_idx, h in enumerate(alt_headers, start=1):
        cell = ws3.cell(row=1, column=c_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        
    for r_idx, alt in enumerate(alerts, start=2):
        row_data = [
            alt.get("alert_id"),
            alt.get("timestamp"),
            alt.get("threat_type"),
            alt.get("severity"),
            f"{int(alt.get('confidence', 0) * 100)}%",
            alt.get("source_ip"),
            alt.get("destination_ip"),
            alt.get("detection_method"),
            alt.get("incident_id") or "UNCLUSTERED",
            "; ".join(alt.get("evidence", []))
        ]
        for c_idx, val in enumerate(row_data, start=1):
            cell = ws3.cell(row=r_idx, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border
            if c_idx == 4 and val == "CRITICAL":
                cell.fill = critical_fill
            elif c_idx == 4 and val == "HIGH":
                cell.fill = high_fill

    # =========================================================================
    # SHEET 4: CTI THREAT INTEL
    # =========================================================================
    ws4 = wb.create_sheet(title="CTI Catalog & Matches")
    ws4.views.sheetView[0].showGridLines = True
    
    cti_headers = ["Indicator", "Type", "Threat Actor", "Campaign", "Severity", "Confidence", "First Seen", "Description"]
    for c_idx, h in enumerate(cti_headers, start=1):
        cell = ws4.cell(row=1, column=c_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        
    for r_idx, ind in enumerate(cti_indicators, start=2):
        row_data = [
            ind.get("indicator"),
            ind.get("type"),
            ind.get("threat_actor"),
            ind.get("campaign"),
            ind.get("severity"),
            f"{int(ind.get('confidence', 0) * 100)}%",
            ind.get("first_seen"),
            ind.get("description")
        ]
        for c_idx, val in enumerate(row_data, start=1):
            cell = ws4.cell(row=r_idx, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border

    # =========================================================================
    # SHEET 5: POWER BI TABULAR DATASET (Ready for Direct Power BI Import)
    # =========================================================================
    ws5 = wb.create_sheet(title="PowerBI_Dataset")
    ws5.views.sheetView[0].showGridLines = True
    
    pbi_headers = [
        "Event_or_Alert_ID", "Record_Type", "Timestamp", "Protocol",
        "Source_IP", "Destination_IP", "Threat_Category", "Severity",
        "Confidence_Score", "Engine", "Is_IOC_Match", "Incident_Ref"
    ]
    for c_idx, h in enumerate(pbi_headers, start=1):
        cell = ws5.cell(row=1, column=c_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        
    pbi_row = 2
    for alt in alerts:
        pbi_data = [
            alt.get("alert_id"),
            "ALERT",
            alt.get("timestamp"),
            "TCP" if "SCAN" in alt.get("threat_type", "") else "HTTP",
            alt.get("source_ip"),
            alt.get("destination_ip"),
            alt.get("threat_type"),
            alt.get("severity"),
            alt.get("confidence", 0.0),
            alt.get("detection_method"),
            "TRUE" if alt.get("ioc_match") else "FALSE",
            alt.get("incident_id") or "NONE"
        ]
        for c_idx, val in enumerate(pbi_data, start=1):
            cell = ws5.cell(row=pbi_row, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border
        pbi_row += 1
        
    for evt in events[:100]:
        pbi_data = [
            evt.get("event_id"),
            "TELEMETRY",
            evt.get("timestamp"),
            evt.get("protocol", "TCP"),
            evt.get("source_ip"),
            evt.get("destination_ip"),
            "NORMAL",
            "INFO",
            1.0,
            evt.get("source", "ZEEK"),
            "FALSE",
            "NONE"
        ]
        for c_idx, val in enumerate(pbi_data, start=1):
            cell = ws5.cell(row=pbi_row, column=c_idx, value=val)
            cell.font = regular_font
            cell.border = thin_border
        pbi_row += 1

    # Auto-adjust column widths across all sheets
    for ws in [ws1, ws2, ws3, ws4, ws5]:
        for col in ws.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                val_str = str(cell.value or '')
                if len(val_str) > max_len and len(val_str) < 60:
                    max_len = len(val_str)
            ws.column_dimensions[col_letter].width = max(max_len + 3, 12)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output
