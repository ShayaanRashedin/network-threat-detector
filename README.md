# Network Threat Detector

A Python-based IDS-style network threat detection prototype that analyzes traffic logs and flags suspicious activity. The project is being built as both a cybersecurity detection tool and a small data pipeline project, with future integration of Apache Airflow, Apache Spark, and Apache NiFi.

## Current Features

- Parses network traffic logs from a CSV file
- Detects possible port scanning behavior
- Suspicious outbound connection detection
- Possible data exfiltration detection
- Prints alerts with source IP, destination IP, and scanned ports
- Beaconing behavior detection

## Planned Features

- SQLite alert storage
- Bash automation
- Support for Wireshark-exported traffic logs
- Apache Airflow workflow orchestration
- Apache Spark support for large-scale log processing
- Apache NiFi support for log ingestion and routing

## Future Data Pipeline Design

The long-term goal is to expand this from a basic Python detection script into a small cybersecurity data pipeline.

```text
Network logs / CSV / Wireshark exports
        ↓
Apache NiFi or file ingestion
        ↓
Python threat detection logic
        ↓
SQLite / CSV / JSON alert storage
        ↓
Apache Airflow scheduled workflow
        ↓
Apache Spark processing for larger datasets