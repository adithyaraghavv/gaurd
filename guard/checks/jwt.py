"""Login-token (JWT) checks.

Offline: decode the configured token (no signature check) and flag weak claims.
Live: confirm the server rejects forged variants of YOUR OWN test token
(alg=none, stripped signature, tampered payload)."""
from __future__ import annotations

import base64
import json
import time

from ..findings import Finding

OK = range(200, 300)
MAX_LIFETIME = 30 * 24 * 3600


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None


def evaluate_token(token: str) -> list[Finding]:
    d = decode(token)
    if d is None:
        return []
    header, payload = d
    out: list[Finding] = []
    if str(header.get("alg", "")).lower() == "none":
        out.append(Finding("jwt", "critical", "Token uses alg=none", "Tokens are unsigned.", "token",
                           fix="Sign tokens with a strong algorithm and reject alg=none."))
    if "exp" not in payload:
        out.append(Finding("jwt", "medium", "Token never expires",
                           "No 'exp' claim; a stolen token works forever.", "token",
                           fix="Set a short expiry (minutes to hours) and use refresh tokens."))
    else:
        start = payload.get("iat", time.time())
        if payload["exp"] - start > MAX_LIFETIME:
            out.append(Finding("jwt", "low", "Token lifetime is very long",
                               f"Lifetime is about {int((payload['exp'] - start) / 86400)} days.", "token",
                               fix="Shorten access-token lifetime; rotate with refresh tokens."))
    return out


def forgeries(token: str) -> list[tuple[str, str]]:
    d = decode(token)
    if d is None:
        return []
    header, payload = d
    h, p, s = token.split(".")
    none_h = _b64e(json.dumps({**header, "alg": "none"}).encode())
    tampered_p = _b64e(json.dumps({**payload, "guard": 1}).encode())
    return [
        ("alg=none", f"{none_h}.{p}."),
        ("signature-stripped", f"{h}.{p}."),
        ("tampered-payload", f"{h}.{tampered_p}.{s}"),
    ]


def run(cfg, http) -> list[Finding]:
    tok = cfg.tenant_a_token
    if not tok:
        return []
    findings = evaluate_token(tok)
    if http is not None and cfg.tenant_a_resources:
        url = cfg.base_url.rstrip("/") + cfg.tenant_a_resources[0]
        base, _, _ = http.request("GET", url, {"Authorization": f"Bearer {tok}"})
        if base in OK:
            for label, forged in forgeries(tok):
                status, _, _ = http.request("GET", url, {"Authorization": f"Bearer {forged}"})
                if status in OK:
                    findings.append(Finding(
                        "jwt", "critical", f"Server accepts forged token ({label})",
                        "A modified token was accepted as valid.", url, evidence=f"status={status}",
                        fix="Verify signatures with a pinned algorithm; never accept alg=none.",
                        tags=["owasp-a07"]))
    return findings
