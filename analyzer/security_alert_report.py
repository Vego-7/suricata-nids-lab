#!/usr/bin/env python3
"""Generate a summary report from structured JSONL security alerts."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


DEFAULT_ALERT_LOG = (
    "/var/log/suricata/ssh_correlated_alerts.jsonl"
)


def load_alerts(log_path):
    """Read and validate JSONL alert records."""
    alerts = []

    with Path(log_path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_number}: {exc}"
                ) from exc

            if not isinstance(alert, dict):
                raise ValueError(
                    f"Invalid alert at line {line_number}: "
                    "expected a JSON object"
                )

            alerts.append(alert)

    return alerts


def summarize_alerts(alerts):
    """Summarize security alerts into report data."""
    event_types = Counter()
    source_ips = Counter()
    usernames = Counter()
    timestamps = []
    time_deltas = []

    for index, alert in enumerate(alerts, start=1):
        event_types[alert.get("event_type", "unknown")] += 1
        source_ips[alert.get("src_ip", "unknown")] += 1
        usernames[alert.get("username", "unknown")] += 1

        raw_timestamp = alert.get("timestamp")
        if raw_timestamp:
            try:
                timestamps.append(
                    datetime.fromisoformat(raw_timestamp)
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid timestamp in alert {index}"
                ) from exc

        delta = alert.get("time_delta_seconds")
        if delta is not None:
            if isinstance(delta, bool) or not isinstance(
                delta, (int, float)
            ):
                raise ValueError(
                    f"Invalid time delta in alert {index}"
                )

            time_deltas.append(delta)

    # Normalize all timestamps to comparable UTC values.
    if timestamps:
        from datetime import timezone

        normalized = [
            ts if ts.tzinfo is not None
            else ts.replace(tzinfo=timezone.utc)
            for ts in timestamps
        ]

        first_alert = min(normalized).isoformat()
        last_alert = max(normalized).isoformat()
    else:
        first_alert = None
        last_alert = None

    average_delta = (
        round(sum(time_deltas) / len(time_deltas), 3)
        if time_deltas else None
    )

    return {
        "total_alerts": len(alerts),
        "event_types": event_types,
        "source_ips": source_ips,
        "usernames": usernames,
        "first_alert": first_alert,
        "last_alert": last_alert,
        "average_time_delta_seconds": average_delta,
    }


def print_counter(title, counts):
    """Print a sorted count table."""
    print(f"\n{title}")

    if not counts:
        print("  (none)")
        return

    for name, count in sorted(
        counts.items(),
        key=lambda item: (-item[1], str(item[0])),
    ):
        print(f"  {name}: {count}")


def print_report(summary):
    """Display the security alert report."""
    print("=" * 50)
    print(" Security Alert Summary Report")
    print("=" * 50)

    print(f"Total Alerts: {summary['total_alerts']}")

    print_counter("Event Types:", summary["event_types"])
    print_counter("Source IPs:", summary["source_ips"])
    print_counter("Usernames:", summary["usernames"])

    print("\nTimeline:")
    print(f"  First Alert: {summary['first_alert'] or 'N/A'}")
    print(f"  Last Alert:  {summary['last_alert'] or 'N/A'}")

    average_delta = summary["average_time_delta_seconds"]
    print("\nCorrelation:")
    if average_delta is None:
        print("  Average Time Difference: N/A")
    else:
        print(f"  Average Time Difference: {average_delta:.3f} seconds")

    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze JSONL security alerts"
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_ALERT_LOG,
        help="Path to JSONL security alert file",
    )

    args = parser.parse_args()

    try:
        alerts = load_alerts(args.log)
        summary = summarize_alerts(alerts)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print_report(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())