"""Mass assignment check. Sends extra privileged fields to your own create/update
endpoints and checks whether the server accepted (echoed) them. Runs against
staging only; it writes data to the endpoints you list."""
from __future__ import annotations

import json

from ..findings import Finding

INJECT = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "tenant_id": "guard-injected",
    "org_id": "guard-injected",
    "owner_id": "guard-injected",
}


def _walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item)


def evaluate(url: str, status: int, body: str) -> list[Finding]:
    if status not in range(200, 300):
        return []
    try:
        data = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return []
    hits = sorted({k for k, v in _walk(data) if k in INJECT and v == INJECT[k]})
    if not hits:
        return []
    return [Finding("mass_assignment", "high", "Server accepted privileged fields from the client",
                    f"Fields {hits} sent by the client were stored/echoed back.", url,
                    evidence=", ".join(hits),
                    fix="Allowlist writable fields per endpoint; set role, tenant and owner on the server only.",
                    tags=["owasp-a01"])]


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"Authorization": f"Bearer {cfg.tenant_a_token}"} if cfg.tenant_a_token else {}
    for t in cfg.mass_assignment_targets:
        url = cfg.base_url.rstrip("/") + t["path"]
        body = {**t.get("body", {}), **INJECT}
        status, _, resp = http.request(t.get("method", "POST").upper(), url, headers, body)
        findings += evaluate(url, status, resp)
    return findings
