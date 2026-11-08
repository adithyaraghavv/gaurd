from __future__ import annotations

from ..findings import Finding


def evaluate(url: str, statuses: list[int]) -> list[Finding]:
    ok = [s for s in statuses if s != 0]
    if ok and 429 not in ok and all(s < 500 for s in ok):
        return [Finding("ratelimit", "medium", "No rate limiting detected",
                        f"{len(ok)} rapid requests all succeeded without a 429.", url,
                        evidence=f"statuses={sorted(set(ok))}",
                        fix="Add per-IP and per-account rate limits on auth and expensive routes.")]
    return []


def run(cfg, http) -> list[Finding]:
    if not cfg.rate_limit_path:
        return []
    url = cfg.base_url.rstrip("/") + cfg.rate_limit_path
    n = min(cfg.rate_limit_attempts, 100)
    statuses = [http.request("POST", url, body={"email": "nobody@example.invalid", "password": "wrong"})[0]
                for _ in range(n)]
    return evaluate(url, statuses)
