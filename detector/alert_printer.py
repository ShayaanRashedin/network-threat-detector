def print_alerts(alerts):
    if not alerts:
        print("No threats detected.")
        return
    
    print("Threats Detected:")
    print("-----------------")

    for alert in alerts:
        print(f"[{alert.get('severity', 'LOW')}] {alert['alert_type']}")
        print(f"Source IP: {alert['src_ip']}")
        print(f"Destination IP: {alert['dst_ip']}")

        if alert["alert_type"] == "Possible Port Scan":
            print(f"Ports Scanned: {alert['ports_scanned']}")
            print(f"Port Count: {alert['port_count']}")
        
        elif alert["alert_type"] == "Suspicious Outbound Connection":
            print(f"Destination Port: {alert['dst_port']}")
            print(f"Reason: {alert['reason']}")

        elif alert["alert_type"] == "Possible Data Exfiltration":
            print(f"Bytes Sent: {alert['bytes_sent']}")
            print(f"Threshold: {alert['threshold']}")
            print(f"Reason: {alert['reason']}")

        elif alert["alert_type"] == "Possible Beaconing Behavior":
            print(f"Connection Count: {alert['connection_count']}")
            print(f"Average Interval: {alert['average_interval_seconds']} seconds")
            print(f"Reason: {alert['reason']}")

        print()