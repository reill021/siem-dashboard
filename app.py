"""
SIEM Dashboard - Flask Backend
Author: Ciarán Reilly
"""

import os
import json
import threading
from flask import Flask, render_template, jsonify, request
from parser.log_parser import LogParser
from parser.detector import ThreatDetector
from alerts.alert_store import AlertStore

app = Flask(__name__)

alert_store = AlertStore()
log_parser  = LogParser()
detector    = ThreatDetector(alert_store)

_stats = {"total_events": 0, "failed_logins": 0, "successful_logins": 0,
          "unique_ips": set(), "alerts_high": 0, "alerts_medium": 0, "alerts_low": 0}
_timeline = []
_top_ips  = {}
_lock     = threading.Lock()


def process_log_file(path: str):
    for event in log_parser.parse_file(path):
        with _lock:
            _stats["total_events"] += 1
            if event["type"] == "failed_login":     _stats["failed_logins"]     += 1
            elif event["type"] == "successful_login":_stats["successful_logins"] += 1
            if event.get("src_ip"):
                _stats["unique_ips"].add(event["src_ip"])
                _top_ips[event["src_ip"]] = _top_ips.get(event["src_ip"], 0) + 1
            hour = event["timestamp"].strftime("%H:00") if event.get("timestamp") else "00:00"
            existing = next((e for e in _timeline if e["hour"] == hour), None)
            if existing: existing["count"] += 1
            else:        _timeline.append({"hour": hour, "count": 1})

        for alert in detector.analyse(event):
            with _lock:
                sev = alert.get("severity", "LOW")
                if sev == "HIGH":     _stats["alerts_high"]   += 1
                elif sev == "MEDIUM": _stats["alerts_medium"] += 1
                else:                 _stats["alerts_low"]    += 1


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    with _lock:
        return jsonify({
            "total_events": _stats["total_events"], "failed_logins": _stats["failed_logins"],
            "successful_logins": _stats["successful_logins"], "unique_ips": len(_stats["unique_ips"]),
            "alerts_high": _stats["alerts_high"], "alerts_medium": _stats["alerts_medium"],
            "alerts_low": _stats["alerts_low"], "total_alerts": alert_store.count(),
        })

@app.route("/api/alerts")
def api_alerts():
    return jsonify(alert_store.get_alerts(
        severity=request.args.get("severity"),
        limit=int(request.args.get("limit", 50))))

@app.route("/api/timeline")
def api_timeline():
    with _lock:
        return jsonify(sorted(_timeline, key=lambda x: x["hour"]))

@app.route("/api/top_ips")
def api_top_ips():
    with _lock:
        return jsonify([{"ip": ip, "count": c}
                        for ip, c in sorted(_top_ips.items(), key=lambda x: x[1], reverse=True)[:10]])

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files or request.files["file"].filename == "":
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    path = os.path.join("logs", file.filename)
    file.save(path)
    threading.Thread(target=process_log_file, args=(path,), daemon=True).start()
    return jsonify({"message": f"Processing {file.filename}"})

@app.route("/api/load_sample")
def api_load_sample():
    sample = os.path.join("logs", "sample_auth.log")
    if not os.path.exists(sample):
        return jsonify({"error": "Sample log not found"}), 404
    with _lock:
        for k in _stats:
            _stats[k] = set() if isinstance(_stats[k], set) else 0
        _timeline.clear(); _top_ips.clear()
    alert_store.clear()
    threading.Thread(target=process_log_file, args=(sample,), daemon=True).start()
    return jsonify({"message": "Sample log loaded"})

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    os.makedirs("alerts", exist_ok=True)
    print("\n  SIEM Dashboard → http://localhost:5000\n")
    app.run(debug=True, port=5000)
