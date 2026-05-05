from detector.log_reader import read_logs
from detector.rules import (
    detect_port_scanning,
    detect_suspicious_outbound,
    detect_data_exfiltration,
    detect_beaconing
)
from detector.alert_printer import print_alerts
from detector.database import initialize_database, save_alerts_to_database

LOG_FILE = "sample_logs.csv"

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