
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Allow tests to import dashboard/app.py from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "dashboard"))

import app as dashboard_app


class DashboardTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.alert_log = Path(self.temp_dir.name) / "alerts.jsonl"

        self.client = dashboard_app.app.test_client()

        self.log_patch = patch.object(
            dashboard_app, "ALERT_LOG", self.alert_log
        )
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)

    def write_alerts(self, alerts):
        with self.alert_log.open("w", encoding="utf-8") as file:
            for alert in alerts:
                file.write(json.dumps(alert) + "\n")

    def sample_alerts(self):
        return [
            {
                "event_type": "correlated_ssh_failure",
                "timestamp": "2026-11-14T09:01:03+00:00",
                "src_ip": "192.168.56.1",
                "src_port": 1295,
                "dest_ip": "192.168.56.10",
                "dest_port": 22,
                "username": "nids-bro",
                "time_delta_seconds": 2.976,
            },
            {
                "event_type": "correlated_ssh_failure",
                "timestamp": "2026-11-14T09:02:00+00:00",
                "src_ip": "192.168.56.1",
                "src_port": 37218,
                "dest_ip": "192.168.56.10",
                "dest_port": 22,
                "username": "nids-bro",
                "time_delta_seconds": 4.295,
            },
            {
                "event_type": "port_scan",
                "timestamp": "2026-11-15T06:49:04+00:00",
                "src_ip": "192.168.56.20",
                "src_port": 55555,
                "dest_ip": "192.168.56.10",
                "dest_port": 80,
                "username": "unknown",
                "time_delta_seconds": 1.0,
            },
        ]

    def test_api_returns_200_and_summary(self):
        self.write_alerts(self.sample_alerts())

        response = self.client.get("/api/alerts/summary")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertEqual(data["total_alerts"], 3)
        self.assertEqual(len(data["alerts"]), 3)
        self.assertEqual(len(data["recent_alerts"]), 3)

    def test_multiple_event_types(self):
        self.write_alerts(self.sample_alerts())

        data = self.client.get(
            "/api/alerts/summary"
        ).get_json()

        self.assertEqual(
            data["event_types"],
            {
                "correlated_ssh_failure": 2,
                "port_scan": 1,
            },
        )

    def test_multiple_source_ips(self):
        self.write_alerts(self.sample_alerts())

        data = self.client.get(
            "/api/alerts/summary"
        ).get_json()

        self.assertEqual(
            data["source_ips"],
            {
                "192.168.56.1": 2,
                "192.168.56.20": 1,
            },
        )

    def test_hourly_timeline(self):
        self.write_alerts(self.sample_alerts())

        data = self.client.get(
            "/api/alerts/summary"
        ).get_json()

        self.assertEqual(
            data["timeline"],
            [
                {
                    "hour": "2026-11-14T09:00:00+00:00",
                    "count": 2,
                },
                {
                    "hour": "2026-11-15T06:00:00+00:00",
                    "count": 1,
                },
            ],
        )

    def test_timezone_normalization(self):
        alerts = [
            {
                "event_type": "test",
                "timestamp": "2026-11-14T16:15:00+07:00",
                "src_ip": "192.168.56.1",
            }
        ]
        self.write_alerts(alerts)

        data = self.client.get(
            "/api/alerts/summary"
        ).get_json()

        self.assertEqual(
            data["timeline"],
            [
                {
                    "hour": "2026-11-14T09:00:00+00:00",
                    "count": 1,
                }
            ],
        )

    def test_empty_log(self):
        self.write_alerts([])

        response = self.client.get("/api/alerts/summary")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertEqual(data["total_alerts"], 0)
        self.assertEqual(data["alerts"], [])
        self.assertEqual(data["timeline"], [])
        self.assertEqual(data["source_ips"], {})

    def test_invalid_json_returns_500(self):
        self.alert_log.write_text(
            '{"event_type":"test"}\nINVALID_JSON\n',
            encoding="utf-8",
        )

        response = self.client.get("/api/alerts/summary")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "Unable to load security alerts"},
        )

    def test_non_object_json_returns_500(self):
        self.alert_log.write_text(
            '["not", "an", "object"]\n',
            encoding="utf-8",
        )

        response = self.client.get("/api/alerts/summary")

        self.assertEqual(response.status_code, 500)

    def test_missing_log_returns_500(self):
        response = self.client.get("/api/alerts/summary")

        self.assertEqual(response.status_code, 500)

    def test_homepage_returns_html(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Suricata NIDS Security Dashboard",
            response.data,
        )


if __name__ == "__main__":
    unittest.main()