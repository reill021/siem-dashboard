import json, os, threading
from datetime import datetime


class AlertStore:
    def __init__(self, path="alerts/alerts.json"):
        self._alerts = []; self._lock = threading.Lock(); self._path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def add(self, severity, rule, source, detail, timestamp=None):
        ts = timestamp.isoformat() if timestamp else datetime.now().isoformat()
        alert = {"id": len(self._alerts)+1, "timestamp": ts,
                 "time": datetime.fromisoformat(ts).strftime("%H:%M:%S"),
                 "severity": severity, "rule": rule, "source": source, "detail": detail}
        with self._lock:
            self._alerts.append(alert)
            self._flush()
        return alert

    def get_alerts(self, severity=None, limit=50):
        with self._lock:
            data = [a for a in self._alerts if not severity or a["severity"] == severity.upper()]
            return list(reversed(data))[:limit]

    def count(self):
        with self._lock: return len(self._alerts)

    def clear(self):
        with self._lock: self._alerts = []; self._flush()

    def _flush(self):
        try:
            with open(self._path, "w") as f: json.dump(self._alerts, f, indent=2)
        except Exception: pass
