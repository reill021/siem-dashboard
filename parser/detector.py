import time
from collections import defaultdict


class ThreatDetector:
    def __init__(self, alert_store):
        self.store = alert_store
        self._failed   = defaultdict(list)
        self._invalid  = defaultdict(list)
        self._sudo_fail= defaultdict(list)
        self._success_ips = set()
        self.BRUTE_THRESHOLD = 5;  self.BRUTE_WINDOW = 60
        self.INV_THRESHOLD   = 3;  self.INV_WINDOW   = 30
        self.SUDO_THRESHOLD  = 3;  self.SUDO_WINDOW  = 60
        self.RISKY = ["passwd","visudo","chmod 777","chown","useradd","userdel",
                      "rm -rf","nc ","ncat","python","bash","sh ","/bin/sh",
                      "/bin/bash","curl","wget"]

    def analyse(self, event):
        rules = {"failed_login": self._brute, "invalid_user": self._invalid_scan,
                 "sudo_command": self._risky_sudo, "sudo_failed": self._sudo_brute,
                 "successful_login": self._success_after_fail}
        fn = rules.get(event.get("type"))
        if fn:
            a = fn(event)
            if a: return [a]
        return []

    def _brute(self, e):
        ip = e.get("src_ip");  now = time.time()
        if not ip: return None
        self._failed[ip] = [t for t in self._failed[ip] if now-t < self.BRUTE_WINDOW]
        self._failed[ip].append(now)
        if len(self._failed[ip]) == self.BRUTE_THRESHOLD:
            return self.store.add("HIGH","SSH Brute Force", ip,
                f"{len(self._failed[ip])} failed logins from {ip} in {self.BRUTE_WINDOW}s", e.get("timestamp"))

    def _invalid_scan(self, e):
        ip = e.get("src_ip");  now = time.time()
        if not ip: return None
        self._invalid[ip] = [t for t in self._invalid[ip] if now-t < self.INV_WINDOW]
        self._invalid[ip].append(now)
        if len(self._invalid[ip]) == self.INV_THRESHOLD:
            return self.store.add("MEDIUM","Invalid User Scan", ip,
                f"{len(self._invalid[ip])} invalid usernames from {ip} in {self.INV_WINDOW}s", e.get("timestamp"))

    def _risky_sudo(self, e):
        cmd  = e.get("command","");  user = e.get("user","unknown")
        for r in self.RISKY:
            if r in cmd:
                return self.store.add("HIGH","Risky Sudo Command", user,
                    f"'{user}' ran high-risk command: {cmd[:80]}", e.get("timestamp"))

    def _sudo_brute(self, e):
        user = e.get("user","unknown");  now = time.time()
        self._sudo_fail[user] = [t for t in self._sudo_fail[user] if now-t < self.SUDO_WINDOW]
        self._sudo_fail[user].append(now)
        if len(self._sudo_fail[user]) == self.SUDO_THRESHOLD:
            return self.store.add("MEDIUM","Sudo Auth Failures", user,
                f"{len(self._sudo_fail[user])} failed sudo attempts by '{user}' in {self.SUDO_WINDOW}s", e.get("timestamp"))

    def _success_after_fail(self, e):
        ip = e.get("src_ip")
        if ip and self._failed.get(ip) and len(self._failed[ip]) >= 2:
            return self.store.add("HIGH","Login After Failures", ip,
                f"Successful login from {ip} after {len(self._failed[ip])} prior failures — possible brute force success",
                e.get("timestamp"))
