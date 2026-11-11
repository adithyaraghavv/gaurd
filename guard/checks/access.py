"""Role-based access check, for apps whose users have roles (staff, client, admin) rather than two tenants.

You list rules in `access_checks`; each names a caller (no token, or one of your named tokens), a path and what
must happen:

  denied   the caller must be refused (401/403/404), or get no data
  empty    the caller may get 200 but with no rows (what row-level security does)
  allowed  the caller must be able to read it (catches a broken token or route)

Example:
  {"name": "client cannot list staff", "path": "/api/staff", "caller": "client", "expect": "denied"}"""
from __future__ import annotations

from ..bodies import is_empty_body
from ..coverage import Skipped
from ..findings import Finding

OK = range(200, 300)
REFUSED = (401, 403, 404)


def evaluate(rule: dict, url: str, status: int, body: str) -> list[Finding]:
    name, caller, expect = rule.get("name") or rule["path"], rule.get("caller", "anonymous"), rule["expect"]
    who = "an unauthenticated caller" if caller == "anonymous" else f"'{caller}'"
    ev = f"{caller} -> {status}, body[:120]={body[:120]!r}"
    if status == 0:
        return [Finding("access", "info", f"Access rule inconclusive: {name}",
                        "The request failed (network error or timeout).", url, evidence=ev)]
    if expect in ("denied", "empty"):
        if status in REFUSED or (status in OK and is_empty_body(body)):
            return []  # refused, or filtered to nothing: both are safe
        if status in OK:
            return [Finding("access", "critical", f"Access rule broken: {name}",
                            f"{who} received data from {url}, but the rule says the result must be {expect}.", url,
                            evidence=ev,
                            fix="Enforce this role check on the server, and with row-level security in the "
                                "database. Do not rely on the front end hiding it.", tags=["owasp-a01"])]
        return [Finding("access", "info", f"Access rule inconclusive: {name}",
                        f"Got status {status}; expected a refusal or an empty result.", url, evidence=ev)]
    # expect == "allowed"
    if status in OK and not is_empty_body(body):
        return []
    if status in OK:
        return [Finding("access", "low", f"Access rule: {name} returned no data",
                        "Allowed, but the body was empty. Use a route that returns data for this role.", url,
                        evidence=ev)]
    return [Finding("access", "medium", f"Access rule broken: {name}",
                    f"{who} should be able to read {url} but got {status}. Either the route is broken for this "
                    "role or the token is wrong or expired.", url, evidence=ev,
                    fix="Check the token for this role and the route's permissions.")]


def run(cfg, http) -> list[Finding]:
    if not cfg.access_checks:
        raise Skipped("no access_checks configured (list rules of caller, path and expected result)")
    findings: list[Finding] = []
    unset: set[str] = set()
    for rule in cfg.access_checks:
        caller = rule.get("caller", "anonymous")
        token = cfg.token(caller)
        if token is None:
            unset.add(caller)
            continue
        url = cfg.base_url.rstrip("/") + rule["path"]
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        status, _, body = http.request(rule.get("method", "GET").upper(), url, headers, rule.get("body"))
        findings += evaluate(rule, url, status, body)
    if unset and len(unset) == len({r.get("caller", "anonymous") for r in cfg.access_checks}):
        raise Skipped("no token is set for: " + ", ".join(sorted(unset)))
    for caller in sorted(unset):
        findings.append(Finding("access", "info", f"Access rules for '{caller}' skipped",
                                f"The token for '{caller}' is not set (check the environment variable).",
                                tags=["coverage-note"]))
    return findings
