"""Low-impact, read-only SQL injection error probe.

Sends a single quote and a boolean-pair to an input and looks for database error signatures or a response
diff. It never sends destructive payloads.

Inputs come from two places:
- `injection_params`: plain query-string parameters on each probe path (`?q=...`).
- `injection_targets`: anything else, written as a template where the text {payload} marks the input. This
  reaches APIs that do not use plain query strings:
    {"path": "/rest/v1/items?name=eq.{payload}"}                               filter syntax
    {"path": "/rpc/search", "method": "POST", "body": {"q": "{payload}"}}     JSON body / function route
  A target may carry its own "token" (a name from `tokens`, or "anonymous")."""
from __future__ import annotations

import re
from urllib.parse import quote

from ..coverage import Skipped
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


PAYLOAD = "{payload}"


def fill(obj, value: str, in_url: bool = False):
    """Replace {payload} everywhere inside a string, list or dict. In a URL the value is percent-encoded."""
    if isinstance(obj, str):
        return obj.replace(PAYLOAD, quote(value, safe="") if in_url else value)
    if isinstance(obj, list):
        return [fill(x, value) for x in obj]
    if isinstance(obj, dict):
        return {k: fill(v, value) for k, v in obj.items()}
    return obj


def target_headers(cfg, target: dict):
    """Headers for one target: its own token if it names one, else the injection check's token."""
    name = target.get("token")
    if name is None:
        return cfg.auth_headers("injection")
    tok = cfg.token(name)
    if tok is None:
        return None
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def run(cfg, http) -> list[Finding]:
    if not cfg.injection_params and not cfg.injection_targets:
        raise Skipped("no injection_params or injection_targets configured")
    findings: list[Finding] = []
    unset = 0
    headers = cfg.auth_headers("injection")
    if cfg.injection_params:
        if headers is None:
            unset += 1
        else:
            for path in cfg.probe_slice():
                for param in cfg.injection_params:
                    base_url = cfg.base_url.rstrip("/") + path

                    def get(val: str) -> str:
                        return http.request("GET", f"{base_url}?{param}={quote(val)}", headers)[2]
                    findings += evaluate(base_url, param, get("1"), get("1'"), get("1 AND 1=1"), get("1 AND 1=2"))
    for t in cfg.injection_targets:
        h = target_headers(cfg, t)
        if h is None:
            unset += 1
            continue
        method = t.get("method", "GET").upper()
        label = f"{method} {t['path'].split('?')[0]}"

        def send(val: str, t=t, h=h, method=method) -> str:
            url = cfg.base_url.rstrip("/") + fill(t["path"], val, in_url=True)
            return http.request(method, url, h, fill(t["body"], val) if t.get("body") is not None else None)[2]
        findings += evaluate(cfg.base_url.rstrip("/") + t["path"].split("{payload}")[0], label,
                             send("1"), send("1'"), send("1 AND 1=1"), send("1 AND 1=2"))
    if unset and not findings and unset == bool(cfg.injection_params) + len(cfg.injection_targets):
        raise Skipped("the token these inputs need is not set (see check_tokens / tokens)")
    return findings
