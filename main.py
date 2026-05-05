import csv
import sqlite3
import json 
from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample_logs.csv"
DATABASE_FILE = "alerts.db"

PORT_SCAN_THRESHOLD = 5
COMMON_PORTS = {22, 25, 53, 80, 443}
DATA_EXFIL_THRESHOLD = 1000000
BEACON_MIN_CONNECTIONS = 4
BEACON_INTERVAL_TOLERANCE = 5

def read_logs(filename):
    logs = []

    with open(filename, "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            row["timestamp"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            row["dst_port"] = int(row["dst_port"])
            row["bytes_sent"] = int(row["bytes_sent"])
            row["bytes_received"] = int(row["bytes_received"])
            logs.append(row)

    return logs

def detect_port_scanning(logs):
    connections = defaultdict(set)

    for log in logs:
        key = (log["src_ip"], log["dst_ip"])
        connections[key].add(log["dst_port"])

    alerts = []

    for (src_ip, dst_ip), ports in connections.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "alert_type": "Possible Port Scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports_scanned": sorted(ports),
                "port_count": len(ports)
            })
        
    return alerts

def is_private_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.20.") or
        ip.startswith("172.21.") or
        ip.startswith("172.22.") or
        ip.startswith("172.23.") or
        ip.startswith("172.24.") or
        ip.startswith("172.25.") or
        ip.startswith("172.26.") or
        ip.startswith("172.27.") or
        ip.startswith("172.28.") or
        ip.startswith("172.29.") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.")
    )

def detect_suspicious_outbound(logs):
    alerts = []

    for log in logs:
        src_ip = log["src_ip"]
        dst_ip = log["dst_ip"]
        dst_port = log["dst_port"]

        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            if dst_port not in COMMON_PORTS:
                alerts.append({
                    "alert_type": "Suspicious Outbound Connection",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "reason": "Internal host connected to external IP on uncommon port"
                })
    
    return alerts

def detect_data_exfiltration(logs):
    alerts = []

    for log in logs:
        src_ip = log["src_ip"]
        dst_ip = log["dst_ip"]
        bytes_sent = log["bytes_sent"]

        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            if bytes_sent >= DATA_EXFIL_THRESHOLD:
                alerts.append({
                    "alert_type": "Possible Data Exfiltration",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "bytes_sent": bytes_sent,
                    "threshold": DATA_EXFIL_THRESHOLD,
                    "reason": "Internal host sent a large amount of data to an external IP"
                })
    
    return alerts

def detect_beaconing(logs):
    alerts = []
    connections = defaultdict(list)

    for log in logs:
        src_ip = log["src_ip"]
        dst_ip = log["dst_ip"]
        timestamp = log["timestamp"]

        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            key = (src_ip, dst_ip)
            connections[key].append(timestamp)

    for (src_ip, dst_ip), timestamps in connections.items():
        if len(timestamps) < BEACON_MIN_CONNECTIONS:
            continue

        timestamps.sort()

        time_differences = []

        for i in range(1, len(timestamps)):
            difference = timestamps[i] - timestamps[i-1]
            time_differences.append(difference.total_seconds())
        
        average_interval = sum(time_differences) / len(time_differences)

        consistent_intervals = 0

        for difference in time_differences:
            if abs(difference - average_interval) <=BEACON_INTERVAL_TOLERANCE:
                consistent_intervals += 1

        if consistent_intervals == len(time_differences):
            alerts.append({
                "alert_type": "Possible Beaconing Behavior",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "connection_count": len(timestamps),
                    "average_interval_seconds": round(average_interval, 2),
                    "reason": "Internal host made repeated connections to the same external IP at regular intervals"
            })

    return alerts

def print_alerts(alerts):
    if not alerts:
        print("No threats detected.")
        return
    
    print("Threats Detected:")
    print("-----------------")

    for alert in alerts:
        print(f"Alert Type: {alert['alert_type']}")
        print(f"Source IP: {alert['src_ip']}")
        print(f"Destination IP: {alert['dst_ip']}")

        if alert["alert_type"] == "Possible Port Scan":
            print(f"Ports Scanned: {alert['ports_scanned']}")
            print(f"Port Count: {alert['port_count']}")
        
        elif alert["alert_type"] == "Suspicious Outbound Connection":
            print(f"Destination Port: {alert['dst_port']}")
            print(f"Reason: {alert['reason']}")

        elif alert["alert_type"] == "Possible Data Exfiltration":
            print(f"BytesSent: {alert['bytes_sent']}")
            print(f"Threshold: {alert['threshold']}")
            print(f"Reason: {alert['reason']}")

        elif alert["alert_type"] == "Possible Beaconing Behavior":
            print(f"Connection Count: {alert['connection_count']}")
            print(f"Average Interval: {alert['average_interval_seconds']} seconds")
            print(f"Reason: {alert['reason']}")

        print()

def initialize_database():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

def save_alerts_to_database(alerts):
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    for alert in alerts:
        alert_type = alert["alert_type"]
        src_ip = alert["src_ip"]
        dst_ip = alert["dst_ip"]

        details = alert.copy()
        details.pop("alert_type", None)
        details.pop("src_ip", None)
        details.pop("dst_ip", None)

        cursor.execute("""
            INSERT INTO alerts (alert_type, src_ip, dst_ip, details, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_type,
            src_ip,
            dst_ip,
            json.dumps(details),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    connection.commit()
    connection.close()

    print(f"Saved {len(alerts)} alert(s) to {DATABASE_FILE}.")

def main():
    initialize_database()

    logs = read_logs(LOG_FILE)

    alerts = []

    port_scan_alerts = detect_port_scanning(logs)
    outbound_alerts = detect_suspicious_outbound(logs)
    data_exfil_alerts = detect_data_exfiltration(logs)
    beaconing_alerts = detect_beaconing(logs)

    alerts.extend(port_scan_alerts)
    alerts.extend(outbound_alerts)
    alerts.extend(data_exfil_alerts)
    alerts.extend(beaconing_alerts)

    print_alerts(alerts)

    if alerts:
        save_alerts_to_database(alerts)

if __name__ == "__main__":
    main()