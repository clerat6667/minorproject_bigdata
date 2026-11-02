#!/bin/bash
# HDFS Directory Initialization for Cybersecurity Big Data Lake
set -e

echo "Waiting for HDFS NameNode to exit safemode..."
hdfs dfsadmin -safemode wait

echo "Creating HDFS directory structure under /security-data/..."
hdfs dfs -mkdir -p /security-data/raw/zeek
hdfs dfs -mkdir -p /security-data/raw/suricata
hdfs dfs -mkdir -p /security-data/processed/network-events
hdfs dfs -mkdir -p /security-data/processed/dns
hdfs dfs -mkdir -p /security-data/processed/http
hdfs dfs -mkdir -p /security-data/alerts
hdfs dfs -mkdir -p /security-data/anomalies
hdfs dfs -mkdir -p /security-data/threat-intelligence
hdfs dfs -mkdir -p /security-data/checkpoints/spark

echo "Setting permissions on /security-data/..."
hdfs dfs -chmod -R 777 /security-data

echo "HDFS initialized successfully! Current directory tree:"
hdfs dfs -ls -R /security-data
