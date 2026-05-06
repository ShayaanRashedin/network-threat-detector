import csv
from datetime import datetime

def read_custom_logs(filename):
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

def read_wireshark_logs(filename):
    logs = []

    with open(filename, "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            try:
                log = {
                    "timestamp": parse_wireshark_timestamp(row),
                    "src_ip": row["Source"],
                    "dst_ip": row["Destination"],
                    "dst_port": parse_destination_port(row),
                    "protocol": row["Protocol"],
                    "bytes_sent": int(row["Length"]),
                    "bytes_recieved": 0
                }

                logs.append(log)

            except (KeyError, ValueError):
                continue

        return logs
    
def parse_wireshark_timestamp(row):
    time_value = row["Time"]

    try:
        return datetime.strptime(time_value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.fromtimestamp(float(time_value))
    
def parse_destination_port(row):
    info = row["Info"]

    if " > " not in info:
        return 0
    
    try:
        destination_part = info.split(" > ")[1]
        destination_port = destination_part.split()[0]
        return int(destination_port)
    except (IndexError, ValueError):
        return 0
