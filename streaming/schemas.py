"""
PySpark Schemas for Kafka Ingestion and Security Telemetry.
"""
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType,
    FloatType, LongType, TimestampType, MapType
)

NETWORK_EVENT_SCHEMA = StructType([
    StructField("event_id", StringType(), False),
    StructField("timestamp", StringType(), True),
    StructField("source_ip", StringType(), True),
    StructField("source_port", IntegerType(), True),
    StructField("destination_ip", StringType(), True),
    StructField("destination_port", IntegerType(), True),
    StructField("protocol", StringType(), True),
    StructField("event_type", StringType(), True),
    StructField("bytes_sent", LongType(), True),
    StructField("bytes_received", LongType(), True),
    StructField("duration", FloatType(), True),
    StructField("status_code", IntegerType(), True),
    StructField("http_uri", StringType(), True),
    StructField("http_method", StringType(), True),
    StructField("query", StringType(), True),
    StructField("rcode_name", StringType(), True),
    StructField("source", StringType(), True)
])

ALERT_SCHEMA = StructType([
    StructField("alert_id", StringType(), False),
    StructField("timestamp", StringType(), True),
    StructField("source_ip", StringType(), True),
    StructField("destination_ip", StringType(), True),
    StructField("threat_type", StringType(), True),
    StructField("severity", StringType(), True),
    StructField("confidence", FloatType(), True),
    StructField("detection_method", StringType(), True),
    StructField("evidence", StringType(), True),
    StructField("ioc_match", StringType(), True)
])
