import re
from datetime import datetime


class LogParser:
    PATTERNS = {
        "failed_login":      re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
        "successful_login":  re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),
        "invalid_user":      re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from ([\d.]+)"),
        "sudo_command":      re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*USER=(\S+).*COMMAND=(.*)"),
        "sudo_failed":       re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*authentication failure.*user=(\S+)"),
        "session_opened":    re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*session opened for user (\S+)"),
    }

    def _parse_ts(self, raw):
        try:
            return datetime.strptime(f"{datetime.now().year} {raw.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

    def parse_line(self, line):
        for etype, pat in self.PATTERNS.items():
            m = pat.search(line)
            if not m: continue
            g  = m.groups()
            ev = {"type": etype, "timestamp": self._parse_ts(g[0]), "raw": line.strip()}
            if etype in ("failed_login", "successful_login", "invalid_user"):
                ev["user"] = g[1]; ev["src_ip"] = g[2]
            elif etype == "sudo_command":
                ev["user"] = g[1]; ev["command"] = g[2].strip(); ev["src_ip"] = None
            elif etype == "sudo_failed":
                ev["user"] = g[1]; ev["src_ip"] = None
            elif etype == "session_opened":
                ev["user"] = g[1]; ev["src_ip"] = None
            return ev
        return None

    def parse_file(self, path):
        events = []
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    ev = self.parse_line(line)
                    if ev: events.append(ev)
        except FileNotFoundError:
            print(f"[LogParser] Not found: {path}")
        return events
