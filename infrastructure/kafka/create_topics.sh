#!/bin/bash
# Script to create Kafka topics for the Big Data Cybersecurity Platform
set -e

echo "Waiting for Kafka broker to become ready..."
/opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list > /dev/null 2>&1
while [ $? -ne 0 ]; do
    echo "Kafka not ready yet, sleeping 2s..."
    sleep 2
    /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list > /dev/null 2>&1
done

echo "Kafka is ready! Creating required cybersecurity topics..."

TOPICS=(
    "network-events"
    "zeek-events"
    "suricata-events"
    "suricata-alerts"
    "dns-events"
    "http-events"
    "anomaly-events"
    "threat-alerts"
    "correlated-incidents"
)

for TOPIC in "${TOPICS[@]}"; do
    echo "Creating topic: $TOPIC"
    /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --create --if-not-exists --topic "$TOPIC" --partitions 2 --replication-factor 1
done

echo "All topics created successfully:"
/opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list
