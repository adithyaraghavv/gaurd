from __future__ import annotations

from ..findings import Finding

EVIL_ORIGIN = "https://evil.invalid"


def evaluate(url: str, headers: dict) -> list[Finding]:
    acao = headers.get("access-control-allow-origin", "")
    creds = headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == EVIL_ORIGIN and creds:
        return [Finding("cors", "high", "CORS reflects arbitrary origin with credentials",
                        "Any website can make credentialed requests and read responses.", url,
                        evidence=f"ACAO={acao}; ACAC=true",
                        fix="Use an explicit origin allowlist; never reflect Origin with credentials.")]
    if acao == EVIL_ORIGIN:
        return [Finding("cors", "low", "CORS reflects arbitrary origin",
                        "Origin is reflected without credentials.", url, evidence=f"ACAO={acao}",
                        fix="Restrict to a known origin allowlist.")]
    if acao == "*" and creds:
        return [Finding("cors", "medium", "Wildcard CORS with credentials header",
                        "Browsers block this, but it signals a misconfiguration.", url,
                        fix="Use an explicit allowlist.")]
    return []


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    for path in cfg.probe_paths[:5]:
        url = cfg.base_url.rstrip("/") + path
        status, hdrs, _ = http.request("GET", url, headers={"Origin": EVIL_ORIGIN})
        if status:
            findings += evaluate(url, hdrs)
    return findings
