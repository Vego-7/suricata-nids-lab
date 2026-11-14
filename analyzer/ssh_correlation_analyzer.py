
import json
from collections import defaultdict
from datetime import datetime

from ssh_failure_analyzer import (
    load_ssh_logs,
    parse_failed_login,
)


# Correlation configuration
SURICATA_EVE_PATH = "/var/log/suricata/eve.json"
SSH_SYN_SIGNATURE_ID = 1000002
SSH_PORT = 22
CORRELATION_WINDOW = 60


def load_suricata_ssh_alerts():
    """Load SSH TCP SYN alerts from Suricata EVE JSON."""
    alerts = []

    with open(SURICATA_EVE_PATH, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            if event.get("alert", {}).get("signature_id") != SSH_SYN_SIGNATURE_ID:
                continue

            if event.get("proto") != "TCP":
                continue

            if event.get("dest_port") != SSH_PORT:
                continue

            try:
                alert = {
                    "time": datetime.fromisoformat(event["timestamp"]),
                    "src_ip": event["src_ip"],
                    "src_port": int(event["src_port"]),
                    "dest_ip": event["dest_ip"],
                    "dest_port": int(event["dest_port"]),
                }
            except (KeyError, ValueError, TypeError):
                continue

            alerts.append(alert)

    return alerts


def load_ssh_failed_logins():
    """Load failed SSH login events using the existing parser."""
    events = []

    for line in load_ssh_logs():
        event = parse_failed_login(line)

        if event is not None:
            events.append(event)

    return events


def correlate_events(suricata_alerts, ssh_events):
    """Match SSH failures to the closest preceding TCP SYN."""
    correlated = []

    # Group network events by source IP and source port
    indexed_alerts = defaultdict(list)

    for alert in suricata_alerts:
        key = (alert["src_ip"], alert["src_port"])
        indexed_alerts[key].append(alert)

    for alerts in indexed_alerts.values():
        alerts.sort(key=lambda item: item["time"])

    # Match each SSH failure with its closest preceding SYN
    for ssh_event in ssh_events:
        key = (ssh_event["src_ip"], ssh_event["src_port"])
        candidates = indexed_alerts.get(key, [])

        best_match = None
        best_delta = None

        for alert in candidates:
            delta = (
                ssh_event["time"] - alert["time"]
            ).total_seconds()

            if delta < 0 or delta > CORRELATION_WINDOW:
                continue

            if best_delta is None or delta < best_delta:
                best_match = alert
                best_delta = delta

        if best_match is not None:
            correlated.append({
                "ssh_time": ssh_event["time"],
                "syn_time": best_match["time"],
                "src_ip": ssh_event["src_ip"],
                "src_port": ssh_event["src_port"],
                "dest_ip": best_match["dest_ip"],
                "dest_port": best_match["dest_port"],
                "username": ssh_event["username"],
                "time_delta": best_delta,
            })

    return correlated


def main():
    print("=" * 45)
    print(" Historical SSH Log Correlation Analyzer")
    print("=" * 45)

    suricata_alerts = load_suricata_ssh_alerts()
    ssh_events = load_ssh_failed_logins()

    print(f"Suricata SSH SYN Alerts: {len(suricata_alerts)}")
    print(f"SSH Failed Login Events: {len(ssh_events)}")

    correlated = correlate_events(
        suricata_alerts,
        ssh_events,
    )

    print(f"Correlated SSH Failures: {len(correlated)}")

    for event in correlated:
        print()
        print("[CORRELATED SSH LOGIN FAILURE]")
        print(f"TCP SYN Time (UTC): {event['syn_time'].isoformat()}")
        print(f"SSH Failure Time (UTC): {event['ssh_time'].isoformat()}")
        print(f"Source: {event['src_ip']}:{event['src_port']}")
        print(f"Destination: {event['dest_ip']}:{event['dest_port']}")
        print(f"Username: {event['username']}")
        print(f"Time Difference: {event['time_delta']:.3f} seconds")
        print("-" * 45)


if __name__ == "__main__":
    main()