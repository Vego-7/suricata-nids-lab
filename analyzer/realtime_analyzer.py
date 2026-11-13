import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Configuration
LOG_FILE = "/var/log/suricata/eve.json"
PORT_THRESHOLD = 10
TIME_WINDOW = 5
SYN_RULE_SID = 1000002
POLL_INTERVAL = 0.2


def parse_alert(line):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    if event.get("proto") != "TCP":
        return None

    if event.get("alert", {}).get("signature_id") != SYN_RULE_SID:
        return None

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    dest_port = event.get("dest_port")
    timestamp = event.get("timestamp")

    if not src_ip or not dest_ip or not timestamp:
        return None

    if not isinstance(dest_port, int):
        return None

    try:
        event_time = datetime.strptime(
            timestamp, "%Y-%m-%dT%H:%M:%S.%f%z"
        )
    except ValueError:
        return None

    return {
        "time": event_time,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
    }


class PortScanDetector:
    def __init__(self):
        self.windows = defaultdict(deque)
        self.port_counts = defaultdict(lambda: defaultdict(int))
        self.detected = defaultdict(bool)

    def process(self, alert):
        key = (alert["src_ip"], alert["dest_ip"])
        window = self.windows[key]
        counts = self.port_counts[key]
        now = alert["time"]

        window.append(alert)
        counts[alert["dest_port"]] += 1

        while window and (
            now - window[0]["time"]
        ) > timedelta(seconds=TIME_WINDOW):
            old = window.popleft()
            port = old["dest_port"]

            counts[port] -= 1

            if counts[port] == 0:
                del counts[port]

        unique_ports = len(counts)
        threshold_reached = unique_ports >= PORT_THRESHOLD

        if threshold_reached and not self.detected[key]:
            print("\n[PORT SCAN-LIKE DETECTED]")
            print(f"Time (UTC): {now.isoformat()}")
            print(f"Source IP: {alert['src_ip']}")
            print(f"Destination IP: {alert['dest_ip']}")
            print(f"Unique Ports: {unique_ports}")
            print(f"Ports: {sorted(counts.keys())}")
            print("-" * 40, flush=True)

        self.detected[key] = threshold_reached


def monitor_log():
    detector = PortScanDetector()

    print("====================================")
    print(" Suricata Real-time Port Scan Monitor")
    print("====================================")
    print(f"Monitoring: {LOG_FILE}")
    print(
        f"Threshold: {PORT_THRESHOLD} unique ports "
        f"within {TIME_WINDOW} seconds"
    )
    print("Waiting for new alerts... (Ctrl+C to stop)")

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        # Start from the end to ignore old events
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            alert = parse_alert(line)

            if alert:
                detector.process(alert)


if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")