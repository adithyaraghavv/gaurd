"""Looks for files and endpoints that should never be public. Each hit is
validated against the response CONTENT, so single-page apps that return 200
for every path do not cause false alarms."""
from __future__ import annotations

import re

from ..findings import Finding

CHECKS = [
    ("/.env", "critical", re.compile(r"^[A-Z][A-Z0-9_]{2,}=.+", re.M), "Environment file exposed"),
    ("/.git/HEAD", "high", re.compile(r"^ref:\s", re.M), "Git repository exposed"),
    ("/.git/config", "high", re.compile(r"\[core\]"), "Git config exposed"),
    ("/backup.sql", "critical", re.compile(r"CREATE TABLE|INSERT INTO", re.I), "Database dump exposed"),
    ("/dump.sql", "critical", re.compile(r"CREATE TABLE|INSERT INTO", re.I), "Database dump exposed"),
    ("/phpinfo.php", "medium", re.compile(r"phpinfo\(\)|PHP Version", re.I), "phpinfo page exposed"),
    ("/actuator/env", "high", re.compile(r"propertySources"), "Spring actuator env exposed"),
    ("/server-status", "medium", re.compile(r"Apache Server Status"), "Server status page exposed"),
    ("/.DS_Store", "low", re.compile(r"Bud1"), "macOS metadata file exposed"),
    ("/swagger.json", "low", re.compile(r'"(swagger|openapi)"'), "API spec is public"),
    ("/openapi.json", "low", re.compile(r'"openapi"'), "API spec is public"),
]


def evaluate(path: str, url: str, status: int, body: str) -> list[Finding]:
    for p, sev, pattern, title in CHECKS:
        if p == path and status == 200 and pattern.search(body):
            return [Finding("exposed", sev, title, f"{path} is publicly readable.", url,
                            fix="Remove the file from the web root/deployment or block it at the server, "
                                "and rotate any secrets it contained.",
                            tags=["owasp-a05"])]
    return []


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    for path, *_ in CHECKS:
        url = cfg.base_url.rstrip("/") + path
        status, _, body = http.request("GET", url)
        findings += evaluate(path, url, status, body)
    return findings
