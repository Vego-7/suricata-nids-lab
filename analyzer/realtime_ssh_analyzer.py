import subprocess
from collections import defaultdict, deque
from datetime import timedelta

from ssh_failure_analyzer import (
    FAILURE_THRESHOLD,
    TIME_WINDOW,
    parse_failed_login,
)


class RealtimeSSHDetector:
    def __init__(self):
        self.windows = defaultdict(deque)
        self.detected = defaultdict(bool)

    def process(self, event):
        src_ip = event["src_ip"]
        event_time = event["time"]

        window = self.windows[src_ip]
        window.append(event)

        # Remove events outside the sliding time window
        while window and (
            event_time - window[0]["time"]
        ) > timedelta(seconds=TIME_WINDOW):
            window.popleft()

        failure_count = len(window)
        threshold_reached = failure_count >= FAILURE_THRESHOLD

        # Alert only when the threshold is first reached
        if threshold_reached and not self.detected[src_ip]:
            print("\n[SSH BRUTE-FORCE-LIKE DETECTED]")
            print(f"Time (UTC): {event_time.isoformat()}")
            print(f"Source IP: {src_ip}")
            print(f"Failed Attempts: {failure_count}")
            print(f"Time Window: {TIME_WINDOW} seconds")
            print(
                "Usernames:",
                sorted({entry["username"] for entry in window}),
            )
            print("-" * 40, flush=True)

        self.detected[src_ip] = threshold_reached


def monitor_ssh_logs():
    detector = RealtimeSSHDetector()

    print("====================================")
    print(" Real-time SSH Login Failure Monitor")
    print("====================================")
    print(f"Threshold: {FAILURE_THRESHOLD} failures")
    print(f"Time Window: {TIME_WINDOW} seconds")
    print("Waiting for new SSH events... (Ctrl+C to stop)", flush=True)

    command = [
        "journalctl",
        "-u", "ssh",
        "-f",
        "-n", "0",
        "-o", "short-iso",
        "--no-pager",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        for line in process.stdout:
            event = parse_failed_login(line)

            if event:
                print(
                    f"[SSH FAILED LOGIN] "
                    f"Time: {event['time'].isoformat()} "
                    f"Source: {event['src_ip']} "
                    f"User: {event['username']}",
                    flush=True,
                )

                detector.process(event)

    finally:
        if process.poll() is None:
            process.terminate()

        process.wait()


if __name__ == "__main__":
    try:
        monitor_ssh_logs()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")