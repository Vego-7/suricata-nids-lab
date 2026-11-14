import json
import os
import queue
import subprocess
import threading
import time

from collections import defaultdict, deque
from datetime import datetime

from ssh_failure_analyzer import parse_failed_login


# Configuration
SURICATA_LOG = "/var/log/suricata/eve.json"

SSH_SYN_SIGNATURE_ID = 1000002
SSH_PORT = 22

CORRELATION_WINDOW = 60
POLL_INTERVAL = 0.2

# Allow events from the two sources to arrive out of order
MATCH_GRACE_SECONDS = 2
PENDING_TIMEOUT = 15
SYN_RETENTION_SECONDS = 120


def parse_suricata_ssh_syn(line):
    """Parse a Suricata TCP SYN alert for SSH."""
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "alert":
        return None

    if event.get("proto") != "TCP":
        return None

    if event.get("dest_port") != SSH_PORT:
        return None

    alert_data = event.get("alert")

    if not isinstance(alert_data, dict):
        return None

    if alert_data.get("signature_id") != SSH_SYN_SIGNATURE_ID:
        return None

    try:
        return {
            "time": datetime.fromisoformat(event["timestamp"]),
            "src_ip": event["src_ip"],
            "src_port": int(event["src_port"]),
            "dest_ip": event["dest_ip"],
            "dest_port": int(event["dest_port"]),
        }
    except (KeyError, ValueError, TypeError):
        return None


class RealtimeSSHCorrelator:
    def __init__(self):
        self.syn_events = defaultdict(deque)
        self.pending_ssh = []

    def add_syn(self, event):
        key = (event["src_ip"], event["src_port"])

        self.syn_events[key].append({
            "event": event,
            "received_at": time.monotonic(),
        })

        print(
            f"[SURICATA SSH SYN] "
            f"{event['src_ip']}:{event['src_port']} -> "
            f"{event['dest_ip']}:{event['dest_port']}",
            flush=True,
        )

    def add_ssh_failure(self, event):
        self.pending_ssh.append({
            "event": event,
            "received_at": time.monotonic(),
        })

        print(
            f"[SSH FAILED LOGIN] "
            f"Source: {event['src_ip']}:{event['src_port']} "
            f"User: {event['username']}",
            flush=True,
        )

    def find_match(self, ssh_event):
        key = (
            ssh_event["src_ip"],
            ssh_event["src_port"],
        )

        best_match = None
        best_delta = None

        for item in self.syn_events.get(key, []):
            syn = item["event"]

            delta = (
                ssh_event["time"] - syn["time"]
            ).total_seconds()

            if not 0 <= delta <= CORRELATION_WINDOW:
                continue

            if best_delta is None or delta < best_delta:
                best_match = syn
                best_delta = delta

        return best_match, best_delta

    def process_pending(self):
        now = time.monotonic()
        remaining = []

        for item in self.pending_ssh:
            ssh_event = item["event"]
            age = now - item["received_at"]

            # Briefly buffer SSH events so SYN events can arrive
            if age < MATCH_GRACE_SECONDS:
                remaining.append(item)
                continue

            syn, delta = self.find_match(ssh_event)

            if syn is not None:
                self.print_correlation(syn, ssh_event, delta)

            elif age < PENDING_TIMEOUT:
                remaining.append(item)

            else:
                print(
                    f"[UNMATCHED SSH FAILURE] "
                    f"{ssh_event['src_ip']}:"
                    f"{ssh_event['src_port']}",
                    flush=True,
                )

        self.pending_ssh = remaining

    def cleanup(self):
        now = time.monotonic()

        for key in list(self.syn_events):
            events = self.syn_events[key]

            while events and (
                now - events[0]["received_at"]
            ) > SYN_RETENTION_SECONDS:
                events.popleft()

            if not events:
                del self.syn_events[key]

    @staticmethod
    def print_correlation(syn, ssh, delta):
        print()
        print("[REAL-TIME CORRELATED SSH FAILURE]")
        print(f"TCP SYN Time (UTC): {syn['time'].isoformat()}")
        print(f"SSH Failure Time (UTC): {ssh['time'].isoformat()}")
        print(f"Source: {ssh['src_ip']}:{ssh['src_port']}")
        print(f"Destination: {syn['dest_ip']}:{syn['dest_port']}")
        print(f"Username: {ssh['username']}")
        print(f"Time Difference: {delta:.3f} seconds")
        print("-" * 45, flush=True)


def follow_suricata(event_queue, stop_event):
    """Follow newly appended Suricata EVE JSON lines."""
    try:
        with open(SURICATA_LOG, "r", encoding="utf-8") as file:
            file.seek(0, os.SEEK_END)

            while not stop_event.is_set():
                line = file.readline()

                if not line:
                    stop_event.wait(POLL_INTERVAL)
                    continue

                event = parse_suricata_ssh_syn(line)

                if event is not None:
                    event_queue.put(("syn", event))

    except OSError as exc:
        event_queue.put(("error", f"Suricata: {exc}"))


def follow_ssh(event_queue, stop_event, process_holder):
    """Follow new SSH authentication entries from journalctl."""
    command = [
        "journalctl",
        "-u", "ssh",
        "-f",
        "-n", "0",
        "-o", "short-iso",
        "--no-pager",
    ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )

        process_holder["process"] = process

        for line in process.stdout:
            if stop_event.is_set():
                break

            event = parse_failed_login(line)

            if event is not None:
                event_queue.put(("ssh", event))

        if not stop_event.is_set():
            event_queue.put((
                "error",
                f"SSH journal follower stopped "
                f"(exit code: {process.poll()})",
            ))

    except OSError as exc:
        event_queue.put(("error", f"OpenSSH: {exc}"))


def main():
    event_queue = queue.Queue()
    stop_event = threading.Event()
    process_holder = {}

    correlator = RealtimeSSHCorrelator()

    print("=" * 45)
    print(" Real-time SSH Log Correlation Monitor")
    print("=" * 45)
    print(f"Suricata Log: {SURICATA_LOG}")
    print(f"Correlation Window: {CORRELATION_WINDOW} seconds")
    print("Waiting for new events... (Ctrl+C to stop)", flush=True)

    threads = [
        threading.Thread(
            target=follow_suricata,
            args=(event_queue, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=follow_ssh,
            args=(event_queue, stop_event, process_holder),
            daemon=True,
        ),
    ]

    try:
        for thread in threads:
            thread.start()

        while True:
            try:
                event_type, event = event_queue.get(
                    timeout=POLL_INTERVAL
                )

                if event_type == "syn":
                    correlator.add_syn(event)

                elif event_type == "ssh":
                    correlator.add_ssh_failure(event)

                elif event_type == "error":
                    raise RuntimeError(event)

            except queue.Empty:
                pass

            correlator.process_pending()
            correlator.cleanup()

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

    finally:
        stop_event.set()

        process = process_holder.get("process")

        if process is not None and process.poll() is None:
            process.terminate()

            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=2)


if __name__ == "__main__":
    main()