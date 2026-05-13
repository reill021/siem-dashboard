# SIEM Log Analyser & Dashboard

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/flask-3.0%2B-lightgrey)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

A Python + Flask web application that parses Linux authentication logs, applies threat detection rules, and presents findings in a live browser-based SIEM dashboard.

Built as part of a cybersecurity portfolio demonstrating skills in log analysis, threat detection, and SOC tooling — directly applicable to SOC analyst and security engineering roles.

---

## Features

- **Log ingestion** — parses Linux `auth.log` and syslog formats into structured events
- **5 detection rules**: SSH brute force, login after failures, risky sudo commands, invalid user scanning, sudo auth failures
- **Live browser dashboard** — stat cards, event timeline chart, severity breakdown, filterable alerts feed, top IPs
- **Upload your own log** or load the built-in sample
- **JSON alert persistence** — SIEM-compatible output
- **Auto-refresh** every 3 seconds

---

## Installation (Kali Linux)

```bash
git clone https://github.com/YOUR-USERNAME/siem-dashboard.git
cd siem-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 app.py
# Open Firefox at http://localhost:5000
```

Click **Load sample log** for an instant demo, or upload your own `/var/log/auth.log`.

---

## Detection Rules

| Rule | Severity | Trigger |
|---|---|---|
| SSH Brute Force | HIGH | 5+ failed logins from same IP in 60s |
| Login After Failures | HIGH | Success after 2+ prior failures |
| Risky Sudo Command | HIGH | wget, curl, useradd, chmod 777, etc. |
| Invalid User Scan | MEDIUM | 3+ invalid usernames from same IP in 30s |
| Sudo Auth Failures | MEDIUM | 3+ failed sudo attempts in 60s |

---

## Author

**Ciarán Reilly** — MSc Software Design with Cyber Security | CompTIA Security+ | CEH  
[LinkedIn](https://linkedin.com/in/YOUR-USERNAME) · [GitHub](https://github.com/YOUR-USERNAME)
