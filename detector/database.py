import sqlite3
import json 
from datetime import datetime

DATABASE_FILE = "alerts.db"

def initialize_database():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
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
        severity = alert.get("severity", "LOW")
        src_ip = alert["src_ip"]
        dst_ip = alert["dst_ip"]

        details = alert.copy()
        details.pop("alert_type", None)
        details.pop("severity", None)
        details.pop("src_ip", None)
        details.pop("dst_ip", None)

        cursor.execute("""
            INSERT INTO alerts (alert_type, severity, src_ip, dst_ip, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert_type,
            severity,
            src_ip,
            dst_ip,
            json.dumps(details),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    connection.commit()
    connection.close()

    print(f"Saved {len(alerts)} alert(s) to {DATABASE_FILE}.")
