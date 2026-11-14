import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Detection configuration
FAILURE_THRESHOLD = 5
TIME_WINDOW = 60

# Match SSH failed password entries
FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<src_ip>\S+) port (?P<src_port>\d+) ssh2"
)


def load_ssh_logs():
    """Read SSH service logs from systemd journal."""
    result = subprocess.run(
        [
            "journalctl",
            "-u", "ssh",
            "-o", "short-iso",
            "--no-pager",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.splitlines()


def parse_failed_login(line):
    """Extract a failed SSH login event from a log line."""
    match = FAILED_PASSWORD_PATTERN.search(line)

    if not match:
        return None

    try:
        timestamp_text = line.split(" ", 1)[0]
        event_time = datetime.fromisoformat(timestamp_text)
    except (ValueError, IndexError):
        return None

    return {
        "time": event_time,
        "username": match.group("username"),
        "src_ip": match.group("src_ip"),
        "src_port": int(match.group("src_port")),
    }


def detect_ssh_failures(events):
    """Detect repeated failed SSH logins by source IP."""
    windows = defaultdict(deque)
    detected = defaultdict(bool)

    for event in sorted(events, key=lambda item: item["time"]):
        src_ip = event["src_ip"]
        event_time = event["time"]

        window = windows[src_ip]
        window.append(event)

        # Remove events older than the time window
        while window and (
            event_time - window[0]["time"]
        ) > timedelta(seconds=TIME_WINDOW):
            window.popleft()

        failure_count = len(window)
        threshold_reached = failure_count >= FAILURE_THRESHOLD

        if threshold_reached and not detected[src_ip]:
            print("\n[SSH BRUTE-FORCE-LIKE DETECTED]")
            print(f"Time (UTC): {event_time.isoformat()}")
            print(f"Source IP: {src_ip}")
            print(f"Failed Attempts: {failure_count}")
            print(f"Time Window: {TIME_WINDOW} seconds")
            print(
                "Usernames:",
                sorted({entry["username"] for entry in window}),
            )
            print("-" * 40)

        detected[src_ip] = threshold_reached


def main():
    print("====================================")
    print(" SSH Login Failure Analyzer")
    print("====================================")
    print(f"Threshold: {FAILURE_THRESHOLD} failures")
    print(f"Time Window: {TIME_WINDOW} seconds")

    try:
        lines = load_ssh_logs()
    except subprocess.CalledProcessError as error:
        print(f"Error reading SSH logs: {error}")
        return

    events = []

    for line in lines:
        event = parse_failed_login(line)
        if event:
            events.append(event)

    print(f"Total Failed Login Events: {len(events)}")

    if not events:
        print("No SSH failed login events found.")
        return

    detect_ssh_failures(events)
    print("\nAnalysis completed.")


if __name__ == "__main__":
    main()
