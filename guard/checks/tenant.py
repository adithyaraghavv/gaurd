"""Tenant isolation (IDOR / broken access control) check.

Needs two accounts from DIFFERENT tenants (e.g. two workspaces or orgs). Tenant A owns
the listed resources. We request each one as: tenant A (must succeed), no
auth (must fail) and tenant B (must fail). Anything else is a finding."""
from __future__ import annotations

from ..findings import Finding


def evaluate(url: str, a_status: int, anon_status: int, b_status: int, b_body: str) -> list[Finding]:
    out: list[Finding] = []
    if a_status not in range(200, 300):
        out.append(Finding("tenant", "info", "Owner could not read own resource",
                           f"Tenant A got {a_status}; test for this resource is inconclusive.", url,
                           fix="Check the resource URL and tenant A token in your config."))
        return out
    if anon_status in range(200, 300):
        out.append(Finding("tenant", "critical", "Resource readable without authentication",
                           "Unauthenticated request returned success.", url,
                           evidence=f"anon status={anon_status}", fix="Require auth on this route."))
    if b_status in range(200, 300):
        out.append(Finding("tenant", "critical", "Cross-tenant data access (IDOR)",
                           "Tenant B read a resource owned by tenant A.", url,
                           evidence=f"tenant B status={b_status}, body[:120]={b_body[:120]!r}",
                           fix="Scope every query by the caller's tenant id server-side; "
                               "enforce row-level security in the database.",
                           tags=["owasp-a01"]))
    return out


def run(cfg, http) -> list[Finding]:
    if not (cfg.tenant_a_token and cfg.tenant_b_token and cfg.tenant_a_resources):
        return [Finding("tenant", "info", "Tenant isolation check skipped",
                        "Set tenant_a_token, tenant_b_token and tenant_a_resources to enable.")]
    findings: list[Finding] = []
    for path in cfg.tenant_a_resources:
        url = cfg.base_url.rstrip("/") + path
        a, _, _ = http.request("GET", url, {"Authorization": f"Bearer {cfg.tenant_a_token}"})
        anon, _, _ = http.request("GET", url)
        b, _, b_body = http.request("GET", url, {"Authorization": f"Bearer {cfg.tenant_b_token}"})
        findings += evaluate(url, a, anon, b, b_body)
    return findings
