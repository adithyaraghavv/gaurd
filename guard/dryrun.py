"""A stand-in HTTP client that records every request a live scan WOULD send and sends none of them.

Requests still go through the scope guard, so a host that would be refused is shown as refused. Responses are all
"no answer", so requests that depend on an earlier answer (for example forged-token retries) cannot be listed."""
from __future__ import annotations

from dataclasses import dataclass

from .scope import Scope, ScopeError

WRITES = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Planned:
    check: str
    method: str
    url: str
    auth: str
    body: str
    refused: str = ""

    @property
    def writes(self) -> bool:
        return self.method in WRITES


class DryRunHTTP:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.plan: list[Planned] = []
        self.current = "?"
        self.last_set_cookies: list[str] = []

    def request(self, method, url, headers=None, body=None):
        refused = ""
        try:
            self.scope.check(url)
        except ScopeError as e:
            refused = str(e)
        h = headers or {}
        auth = "bearer token" if "Authorization" in h else "none"
        shown = ""
        if isinstance(body, dict):
            shown = "JSON body: " + ", ".join(sorted(body)[:8])
        elif isinstance(body, bytes):
            shown = f"{len(body)} bytes"
        self.plan.append(Planned(self.current, method.upper(), url, auth, shown, refused))
        return 0, {}, "dry run: nothing was sent"


def format_plan(plan: list[Planned]) -> str:
    if not plan:
        return "No live requests would be sent (no live check is configured to run)."
    lines = [f"A live scan would send {len(plan)} request(s). Nothing was sent.", ""]
    by: dict[str, list[Planned]] = {}
    for p in plan:
        by.setdefault(p.check, []).append(p)
    for check, items in by.items():
        writes = sum(1 for i in items if i.writes)
        lines.append(f"{check}: {len(items)} request(s)" + (f", {writes} WRITE DATA" if writes else ""))
        seen = set()
        for i in items:
            key = (i.method, i.url, i.auth, i.body)
            if key in seen:
                continue
            seen.add(key)
            n = sum(1 for x in items if (x.method, x.url, x.auth, x.body) == key)
            flag = "  <- REFUSED: " + i.refused if i.refused else ("  <- writes data" if i.writes else "")
            lines.append(f"  {i.method:6} {i.url}  auth: {i.auth}" + (f"  ({i.body})" if i.body else "")
                         + (f"  x{n}" if n > 1 else "") + flag)
    refused = sum(1 for p in plan if p.refused)
    if refused:
        lines += ["", f"{refused} request(s) would be REFUSED by the scope guard (host not allowed or looks like production)."]
    lines += ["", "Requests that depend on an earlier answer (such as forged-token retries) cannot be listed."]
    return "\n".join(lines)
