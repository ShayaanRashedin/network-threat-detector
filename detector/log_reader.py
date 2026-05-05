import csv
from datetime import datetime

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