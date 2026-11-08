"""Low-impact, read-only SQL injection error probe.

Sends a single quote and a boolean-pair to GET params and looks for database
error signatures or a response diff. It never sends destructive payloads."""
from __future__ import annotations

import re
from urllib.parse import quote

from ..findings import Finding

DB_ERRORS = re.compile(
    r"(sql syntax|syntax error at or near|unterminated quoted string|"
    r"psycopg2\.errors|pg_query\(\)|sqlite3\.OperationalError|SQLSTATE\[|"
    r"ORA-\d{5}|mysql_fetch|unclosed quotation mark|PostgREST|invalid input syntax)",
    re.I,
)


def evaluate(url: str, param: str, base_body: str, quote_body: str, true_body: str, false_body: str) -> list[Finding]:
    out: list[Finding] = []
    m = DB_ERRORS.search(quote_body)
    if m and not DB_ERRORS.search(base_body):
        out.append(Finding("injection", "high", "Possible SQL injection (error-based)",
                           f"Param '{param}' produced a database error after a single quote.", url,
                           evidence=m.group(0),
                           fix="Use parameterized queries / ORM bindings; never build SQL with string concatenation.",
                           tags=["owasp-a03"]))
    elif true_body and false_body and true_body != base_body and len(true_body) != len(false_body) \
            and abs(len(true_body) - len(base_body)) < 50:
        out.append(Finding("injection", "medium", "Possible boolean-based SQL injection",
                           f"Param '{param}' responds differently to true/false conditions.", url,
                           evidence=f"len(true)={len(true_body)} len(false)={len(false_body)}",
                           fix="Confirm manually; switch to parameterized queries.", tags=["owasp-a03"]))
    return out


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"Authorization": f"Bearer {cfg.tenant_a_token}"} if cfg.tenant_a_token else {}
    for path in cfg.probe_paths[:5]:
        for param in cfg.injection_params:
            base_url = cfg.base_url.rstrip("/") + path
            def get(val: str) -> str:
                return http.request("GET", f"{base_url}?{param}={quote(val)}", headers)[2]
            findings += evaluate(base_url, param, get("1"), get("1'"), get("1 AND 1=1"), get("1 AND 1=2"))
    return findings
