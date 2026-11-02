# Zeek Local Policy Configuration for JSON Logging & Threat Detection
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/frameworks/notice
@load policy/misc/scan

# Force all Zeek logs to output in JSON format for streaming ingestion
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
