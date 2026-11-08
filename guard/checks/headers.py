from __future__ import annotations

from ..findings import Finding

REQUIRED = {
    "strict-transport-security": ("medium", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "x-content-type-options": ("low", "Add 'X-Content-Type-Options: nosniff'."),
    "content-security-policy": ("medium", "Add a restrictive Content-Security-Policy."),
    "referrer-policy": ("low", "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
}
LEAKY = ("server", "x-powered-by")


def evaluate(url: str, headers: dict) -> list[Finding]:
    out: list[Finding] = []
    for name, (sev, fix) in REQUIRED.items():
        if name not in headers:
            out.append(Finding("headers", sev, f"Missing {name}", f"{url} does not send {name}.", url, fix=fix))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        out.append(Finding("headers", "low", "No clickjacking protection", f"{url} can be framed.", url,
                           fix="Add 'X-Frame-Options: DENY' or CSP frame-ancestors."))
    for name in LEAKY:
        val = headers.get(name, "")
        if any(ch.isdigit() for ch in val):
            out.append(Finding("headers", "low", f"Version disclosure via {name}", f"{name}: {val}", url,
                               evidence=val, fix=f"Remove or genericize the {name} header."))
    return out


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    for path in cfg.probe_paths[:5]:
        url = cfg.base_url.rstrip("/") + path
        status, hdrs, _ = http.request("GET", url)
        if status == 0:
            continue
        findings += evaluate(url, hdrs)
    return findings
