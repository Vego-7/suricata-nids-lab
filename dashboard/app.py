
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)

ALERT_LOG = Path("/var/log/suricata/ssh_correlated_alerts.jsonl")


def load_alerts():
    """Read security alerts from the JSONL log."""
    alerts = []

    with ALERT_LOG.open("r", encoding="utf-8") as file:
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
                    "expected JSON object"
                )

            alerts.append(alert)

    return alerts


def build_timeline(alerts):
    """Count security alerts per UTC hour."""
    hourly_counts = Counter()

    for alert in alerts:
        timestamp = alert.get("timestamp")

        if not isinstance(timestamp, str):
            continue

        try:
            event_time = datetime.fromisoformat(timestamp)
        except ValueError:
            continue

        if event_time.tzinfo is None:
            continue

        hour = (
            event_time.astimezone(timezone.utc)
            .replace(minute=0, second=0, microsecond=0)
        )

        hourly_counts[hour.isoformat()] += 1

    return [
        {"hour": hour, "count": hourly_counts[hour]}
        for hour in sorted(hourly_counts)
    ]


def count_field(alerts, field):
    """Count string values for a security alert field."""
    counts = Counter()

    for alert in alerts:
        value = alert.get(field)

        if not isinstance(value, str) or not value:
            value = "unknown"

        counts[value] += 1

    return dict(counts)


def build_summary(alerts):
    """Build dashboard statistics and alert details."""
    return {
        "total_alerts": len(alerts),
        "event_types": count_field(alerts, "event_type"),
        "source_ips": count_field(alerts, "src_ip"),
        "usernames": count_field(alerts, "username"),
        "timeline": build_timeline(alerts),
        "recent_alerts": alerts[-10:][::-1],
        "alerts": alerts[::-1],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts/summary")
def alert_summary():
    try:
        alerts = load_alerts()
        summary = build_summary(alerts)

    except (OSError, ValueError, TypeError):
        app.logger.exception("Failed to load security alerts")
        return jsonify(
            {"error": "Unable to load security alerts"}
        ), 500

    return jsonify(summary)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )