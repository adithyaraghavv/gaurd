from __future__ import annotations

import re

from ..findings import Finding

SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login", re.I)


def parse_cookie(raw: str) -> tuple[str, dict]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    flags = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        flags[k.lower()] = v
    return name, flags


def evaluate(url: str, cookies: list[str]) -> list[Finding]:
    out: list[Finding] = []
    https = url.startswith("https")
    for raw in cookies:
        name, flags = parse_cookie(raw)
        important = bool(SESSIONISH.search(name))
        hi = "medium" if important else "low"
        if "httponly" not in flags:
            out.append(Finding("cookies", hi, f"Cookie '{name}' missing HttpOnly",
                               "Scripts on the page can read this cookie.", url,
                               fix="Set the HttpOnly flag."))
        if https and "secure" not in flags:
            out.append(Finding("cookies", hi, f"Cookie '{name}' missing Secure",
                               "Cookie can be sent over plain HTTP.", url, fix="Set the Secure flag."))
        samesite = flags.get("samesite", "").lower()
        if not samesite:
            out.append(Finding("cookies", "low", f"Cookie '{name}' missing SameSite",
                               "Cookie is sent on cross-site requests (CSRF risk).", url,
                               fix="Set SameSite=Lax or Strict."))
        elif samesite == "none" and "secure" not in flags:
            out.append(Finding("cookies", "medium", f"Cookie '{name}' SameSite=None without Secure",
                               "Browsers reject this and it signals misconfiguration.", url,
                               fix="Add Secure or use SameSite=Lax."))
    return out


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path in cfg.probe_slice():
        url = cfg.base_url.rstrip("/") + path
        http.request("GET", url)
        for f in evaluate(url, http.last_set_cookies):
            key = (f.title, f.check)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    return findings
