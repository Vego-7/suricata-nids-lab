import json
from collections import Counter
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
                    f"Invalid alert at line {line_number}: expected JSON object"
                )

            alerts.append(alert)

    return alerts


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts/summary")
def alert_summary():
    try:
        alerts = load_alerts()
    except (OSError, ValueError):
        app.logger.exception("Failed to load security alerts")
        return jsonify({"error": "Unable to load security alerts"}), 500

    event_types = Counter(
        alert.get("event_type", "unknown") for alert in alerts
    )
    source_ips = Counter(
        alert.get("src_ip", "unknown") for alert in alerts
    )
    usernames = Counter(
        alert.get("username", "unknown") for alert in alerts
    )

    return jsonify(
        {
            "total_alerts": len(alerts),
            "event_types": dict(event_types),
            "source_ips": dict(source_ips),
            "usernames": dict(usernames),
            "recent_alerts": alerts[-10:][::-1],
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)