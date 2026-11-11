"""Tenant isolation (IDOR / broken access control) check.

Needs two accounts from DIFFERENT tenants (e.g. two workspaces or orgs). Tenant A owns
the listed resources. We request each one as: tenant A (must succeed), no
auth (must fail) and tenant B (must fail).

"Fail" means either an error status or a success that carries no data: row-level security often answers a
caller who may not see the rows with `200 []`, which is correct. Only a response that actually contains data
is a leak."""
from __future__ import annotations

from ..bodies import is_empty_body
from ..coverage import Skipped
from ..findings import Finding

OK = range(200, 300)


def evaluate(url: str, a_status: int, anon_status: int, b_status: int, b_body: str,
             anon_body: str = "x", a_body: str = "x") -> list[Finding]:
    """`anon_body` and `a_body` default to "has content" so callers that only know statuses behave as before."""
    out: list[Finding] = []
    if a_status not in OK:
        out.append(Finding("tenant", "info", "Owner could not read own resource",
                           f"Tenant A got {a_status}; test for this resource is inconclusive.", url,
                           fix="Check the resource URL and tenant A token in your config."))
        return out
    if is_empty_body(a_body):
        out.append(Finding("tenant", "info", "Owner got an empty response for own resource",
                           "Tenant A's own request returned no data, so a 200 for tenant B proves nothing "
                           "here. Use a resource that really has data.", url,
                           fix="Pick a resource URL for tenant A that returns data."))
        return out
    if anon_status in OK:
        if is_empty_body(anon_body):
            out.append(Finding("tenant", "info", "Unauthenticated request got 200 with an empty body",
                               "No data was returned, which is what row-level security does for a caller with no "
                               "rights. Not a leak; a 401 would be clearer.", url,
                               evidence=f"anon status={anon_status}, body[:120]={anon_body[:120]!r}"))
        else:
            out.append(Finding("tenant", "critical", "Resource readable without authentication",
                               "Unauthenticated request returned data.", url,
                               evidence=f"anon status={anon_status}", fix="Require auth on this route."))
    if b_status in OK:
        if is_empty_body(b_body):
            out.append(Finding("tenant", "info", "Other tenant got 200 with an empty body",
                               "Tenant B received no data. That is correct row-level-security behavior, not a "
                               "leak; a 403 or 404 would be clearer.", url,
                               evidence=f"tenant B status={b_status}, body[:120]={b_body[:120]!r}"))
        else:
            out.append(Finding("tenant", "critical", "Cross-tenant data access (IDOR)",
                               "Tenant B read a resource owned by tenant A.", url,
                               evidence=f"tenant B status={b_status}, body[:120]={b_body[:120]!r}",
                               fix="Scope every query by the caller's tenant id server-side; "
                                   "enforce row-level security in the database.",
                               tags=["owasp-a01"]))
    return out


def run(cfg, http) -> list[Finding]:
    missing = [n for n, v in (("tenant_a_token", cfg.tenant_a_token), ("tenant_b_token", cfg.tenant_b_token),
                              ("tenant_a_resources", cfg.tenant_a_resources)) if not v]
    if missing:
        raise Skipped("not set: " + ", ".join(missing) + " (apps with roles instead of tenants: use access_checks)")
    findings: list[Finding] = []
    for path in cfg.tenant_a_resources:
        url = cfg.base_url.rstrip("/") + path
        a, _, a_body = http.request("GET", url, {"Authorization": f"Bearer {cfg.tenant_a_token}"})
        anon, _, anon_body = http.request("GET", url)
        b, _, b_body = http.request("GET", url, {"Authorization": f"Bearer {cfg.tenant_b_token}"})
        findings += evaluate(url, a, anon, b, b_body, anon_body, a_body)
    return findings
