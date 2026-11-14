import json
from datetime import datetime
from pathlib import Path


# Default output location on Ubuntu Server
DEFAULT_ALERT_LOG = (
    "/var/log/suricata/ssh_correlated_alerts.jsonl"
)


def serialize_event(event):
    """Convert a security event into a JSON-compatible dict."""

    serialized = {}

    for key, value in event.items():
        if isinstance(value, datetime):
            serialized[key] = value.isoformat()
        else:
            serialized[key] = value

    return serialized


def write_json_alert(event, log_path=DEFAULT_ALERT_LOG):
    """Append one security event as a JSON line."""

    if not isinstance(event, dict):
        raise TypeError("Security event must be a dictionary")

    if not event:
        raise ValueError("Security event cannot be empty")

    serialized = serialize_event(event)

    # Convert event to JSON before opening the output file
    json_line = json.dumps(
        serialized,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )

    path = Path(log_path)

    try:
        with path.open("a", encoding="utf-8") as file:
            file.write(json_line + "\n")
            file.flush()

    except OSError as exc:
        raise OSError(
            f"Failed to write JSON alert to {path}: {exc}"
        ) from exc

    return path