from collections import defaultdict

PORT_SCAN_THRESHOLD = 5
COMMON_PORTS = {22, 25, 53, 80, 443}
DATA_EXFIL_THRESHOLD = 1000000
BEACON_MIN_CONNECTIONS = 4
BEACON_INTERVAL_TOLERANCE = 5

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