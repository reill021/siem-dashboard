# Troubleshooting Notes

Real issues encountered during development and testing on Kali Linux.

## Issue 1 — PEP 668 Package Installation
**Problem:** pip install flask returned error about system managed packages.  
**Fix:** Use a virtual environment: python3 -m venv venv && source venv/bin/activate

## Issue 2 — Extra Nested Folder
**Problem:** Project was inside an extra siem-dashboard subfolder after unzipping.  
**Fix:** cd siem-dashboard to navigate into the correct directory before running.

## Tested On
- Kali Linux 2026
- Python 3.13
- Flask 3.1.3
