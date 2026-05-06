import argparse

from detector.log_reader import read_custom_logs, read_wireshark_logs
from detector.rules import (
    detect_port_scanning,
    detect_suspicious_outbound,
    detect_data_exfiltration,
    detect_beaconing
)
from detector.alert_printer import print_alerts
from detector.database import initialize_database, save_alerts_to_database

def load_logs(filename, log_format):
    if log_format == "custom":
        return read_custom_logs(filename)
    
    if log_format == "wireshark":
        return read_wireshark_logs(filename)
    
    raise ValueError("Unsupported log format")

def main():
    parser = argparse.ArgumentParser(description="Network Threat Detector")
    
    parser.add_argument(
        "--file",
        default="sample_logs.csv",
        help="Path to the log file to analyze"
    )

    parser.add_argument(
        "--format",
        choices=["custom", "wireshark"],
        default="custom",
        help="Log format: custom or wireshark"
    )

    args = parser.parse_args()

    initialize_database()

    logs = load_logs(args.file, args.format)

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