# Suricata NIDS Lab

A hands-on Network Intrusion Detection System (NIDS) lab built with Suricata, Python, Flask, and systemd on Ubuntu Server.

The project monitors network traffic and SSH authentication activity, correlates related security events, stores structured alerts, and displays the results through a web dashboard.

> This project is intended for learning, testing, and authorized security monitoring in an isolated lab environment.

## Features

- Network intrusion detection using Suricata IDS
- TCP SYN and port-scan activity analysis
- SSH failed-login monitoring
- Historical and real-time security log analysis
- Correlation of Suricata TCP SYN events with SSH authentication failures
- Structured security alerts stored in JSON Lines (JSONL)
- Flask dashboard with interactive charts and alert details
- Filtering by event type and source IP
- Automated dashboard tests using Python unittest
- Automatic service startup using systemd

## Architecture

```text
Windows Host (192.168.56.1)
          |
          | Lab network traffic / SSH
          v
Ubuntu Server VM (192.168.56.10)
          |
          +--> Suricata IDS
          |       |
          |       v
          |   /var/log/suricata/eve.json
          |       |
          |       +------------------+
          |                          |
          +--> SSH Authentication    |
                  Logs              |
                    |               |
                    +-------+-------+
                            |
                            v
                  Python Correlation
                         Engine
                            |
                            v
             ssh_correlated_alerts.jsonl
                            |
                            v
                   Flask Dashboard
                    (Gunicorn)
                            |
                            v
                    127.0.0.1:5000
                            |
                       SSH Tunnel
                            |
                            v
                      Web Browser
```

## Technology Stack

| Component | Technology |
| --- | --- |
| Operating system | Ubuntu Server 24.04 |
| Network IDS | Suricata 7.0.3 |
| Log analysis | Python 3 |
| Web application | Flask 3.1.3 |
| Application server | Gunicorn 27.0.1 |
| Service management | systemd |
| Virtualization | VirtualBox |
| Version control | Git and GitHub |

## Project Structure

```text
suricata-nids-lab/
├── analyzer/
│   ├── json_alert_writer.py
│   ├── port_scan_analyzer.py
│   ├── realtime_analyzer.py
│   ├── realtime_ssh_analyzer.py
│   ├── realtime_ssh_correlation.py
│   ├── security_alert_report.py
│   ├── ssh_correlation_analyzer.py
│   └── ssh_failure_analyzer.py
├── dashboard/
│   ├── app.py
│   └── templates/
│       └── index.html
├── systemd/
│   ├── nids-correlation.service
│   └── nids-dashboard.service
├── tests/
│   └── test_dashboard.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Lab Network

The tested environment uses a VirtualBox host-only network.

| Device | IP Address | Role |
| --- | --- | --- |
| Windows host | 192.168.56.1 | Test traffic generator |
| Ubuntu VM | 192.168.56.10 | NIDS and dashboard server |

The Ubuntu VM monitors the host-only interface `enp0s8`.

These IP addresses and interface names are examples from the tested lab. Adjust them for your environment.

## Prerequisites

- Ubuntu Server with Suricata installed and configured
- Python 3 and Python virtual environment support
- Access to SSH authentication logs
- A network interface receiving the traffic being monitored
- Git
- An isolated or otherwise authorized testing environment

Suricata installation, detection rules, network interfaces, and log permissions must be configured for your environment. These system-level settings are not automatically installed by this repository.

## Python Installation

Clone the repository:

```bash
git clone <your-repository-url>
cd suricata-nids-lab
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Install the Python dependencies:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Dashboard

The dashboard reads structured alerts from:

```text
/var/log/suricata/ssh_correlated_alerts.jsonl
```

Start the dashboard manually for local testing:

```bash
.venv/bin/gunicorn \
  --chdir dashboard \
  --bind 127.0.0.1:5000 \
  --workers 1 \
  app:app
```

Test the API:

```bash
curl http://127.0.0.1:5000/api/alerts/summary
```

The dashboard includes:

- Security alert summary
- Recent alert history
- Hourly event timeline
- Source IP analysis
- Event type and source IP filters
- Search and detailed alert views
- Automatic data refresh

## Real-time SSH Correlation

The real-time correlation engine reads Suricata network events and SSH authentication logs.

A correlated SSH failure is generated when a matching TCP SYN event and SSH failed-login event satisfy the correlation rules, including source IP, source port, and the configured time window.

The tested correlation window is 60 seconds.

Run the correlation engine manually in the lab:

```bash
sudo python3 -u analyzer/realtime_ssh_correlation.py
```

The engine appends correlated alerts to:

```text
/var/log/suricata/ssh_correlated_alerts.jsonl
```

A correlation alert can contain the event type, source and destination addresses, source port, destination port, username, timestamp, and time difference.

## systemd Deployment

Two systemd unit files are included:

- `nids-dashboard.service` — Flask dashboard served by Gunicorn
- `nids-correlation.service` — Real-time SSH correlation engine

The provided service files use the tested Ubuntu username and project path:

```text
/home/nids-bro/suricata-nids-lab
```

**Update the service files before installation if your username or installation path differs.**

Install both service definitions:

```bash
sudo install -m 644 systemd/nids-dashboard.service /etc/systemd/system/nids-dashboard.service
sudo install -m 644 systemd/nids-correlation.service /etc/systemd/system/nids-correlation.service
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable and start the services:

```bash
sudo systemctl enable --now nids-dashboard.service
sudo systemctl enable --now nids-correlation.service
```

Check their status:

```bash
systemctl status nids-dashboard.service --no-pager
systemctl status nids-correlation.service --no-pager
```

Inspect service logs:

```bash
sudo journalctl -u nids-dashboard.service -n 30 --no-pager
sudo journalctl -u nids-correlation.service -n 30 --no-pager
```

The dashboard service runs as the non-root `nids-bro` user. The supplied correlation service runs as `root` because the current lab implementation requires access to SSH journal records and Suricata alert files.

For a production deployment, review and reduce service privileges, protect log files, and apply additional security controls.

## Accessing the Dashboard from Windows

The dashboard listens only on Ubuntu's loopback address:

```text
127.0.0.1:5000
```

From Windows PowerShell, create an SSH tunnel:

```powershell
ssh -N -L 5000:127.0.0.1:5000 nids-bro@192.168.56.10
```

Then open this address in the Windows browser:

```text
http://127.0.0.1:5000
```

Keep the SSH tunnel connected while using the dashboard.

## Automated Tests

Dashboard tests use Python's built-in `unittest` framework and Flask's test client.

Run the test suite from the repository root:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The dashboard suite was tested successfully with 10 passing tests.

## Verified Lab Results

The following behaviors were verified in the test environment:

- Suricata detects relevant network events.
- SSH authentication failures appear in system logs.
- The correlation engine matches Suricata and SSH events.
- Correlated alerts are saved to JSONL.
- The dashboard API displays stored alerts.
- Dashboard and correlation services start automatically after reboot.
- The dashboard API returns HTTP 200 after reboot.
- An end-to-end SSH test increased the dashboard alert count from 3 to 4.

## Security Considerations

- Use this project only on systems and networks you own or are authorized to test.
- Do not expose the development dashboard directly to untrusted networks.
- Prefer an SSH tunnel for remote access to the local dashboard.
- Restrict access to authentication logs and security alert files.
- Review the privileges of systemd services before production use.
- Avoid committing private keys, passwords, raw authentication logs, or sensitive alert data.
- Treat the repository as a learning lab, not a production-ready security monitoring platform.

## Future Improvements

- Additional automated tests for detection and correlation components
- Configurable paths and detection thresholds
- Stronger least-privilege service permissions
- Authentication and authorization for the dashboard
- Alert notifications and long-term log retention
- Additional network attack detection scenarios

## License

No license has been specified for this repository.
