import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Configuration
LOG_FILE = "/var/log/suricata/eve.json"
PORT_THRESHOLD = 10
TIME_WINDOW = 5
SYN_RULE_SID = 1000002


def log_alerts():
    alerts = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            if event.get("proto") != "TCP":
                continue

            alert_info = event.get("alert", {})

            if alert_info.get("signature_id") != SYN_RULE_SID:
                continue

            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")
            dest_port = event.get("dest_port")
            timestamp = event.get("timestamp")

            if not all([src_ip, dest_ip, timestamp]):
                continue

            if not isinstance(dest_port, int):
                continue

            try:
                event_time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )
            except ValueError:
                continue

            alerts.append({
                "time": event_time,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port
            })

    return alerts


def detect_port_scan(alerts):
    grouped = defaultdict(list)

    for alert in alerts:
        key = (alert["src_ip"], alert["dest_ip"])
        grouped[key].append(alert)

    detections = []

    for (src_ip, dest_ip), events in grouped.items():
        events.sort(key=lambda x: x["time"])

        window = deque()
        port_counts = defaultdict(int)
        previously_detected = False

        for event in events:
            current_time = event["time"]
            current_port = event["dest_port"]

            window.append(event)
            port_counts[current_port] += 1

            while window and (
                current_time - window[0]["time"]
            ) > timedelta(seconds=TIME_WINDOW):
                old_event = window.popleft()
                old_port = old_event["dest_port"]

                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

            unique_ports = len(port_counts)
            threshold_reached = unique_ports >= PORT_THRESHOLD

            if threshold_reached and not previously_detected:
                detections.append({
                    "time": current_time,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "unique_ports": unique_ports,
                    "ports": sorted(port_counts.keys())
                })

            previously_detected = threshold_reached

    return detections


def main():
    print("====================================")
    print(" Suricata NIDS - Port Scan Analyzer")
    print("====================================")

    alerts = log_alerts()
    print(f"TCP SYN Alerts loaded: {len(alerts)}")

    detections = detect_port_scan(alerts)

    print(f"Port Scan-like Detections: {len(detections)}")

    if not detections:
        print("No Port Scan-like activity detected.")
        return

    for index, detection in enumerate(detections, start=1):
        print("\n------------------------------------")
        print(f"Detection #{index}")
        print(f"Time (UTC): {detection['time'].isoformat()}")
        print(f"Source IP: {detection['src_ip']}")
        print(f"Destination IP: {detection['dest_ip']}")
        print(f"Unique Destination Ports: {detection['unique_ports']}")
        print(f"Ports: {detection['ports']}")

    print("\nAnalysis completed.")


if __name__ == "__main__":
    main()

