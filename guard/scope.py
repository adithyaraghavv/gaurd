"""Scope guard. Every network check goes through ScopedHTTP, which refuses
any host that is not explicitly allowlisted in the config. This is the main
safety feature: the kit cannot be pointed at a system you did not list."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

PROD_HINTS = ("prod", "production", "www.", "app.")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ScopeError(Exception):
    pass


@dataclass
class Scope:
    allowed_hosts: list[str]
    allow_production: bool = False

    def check(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            raise ScopeError(f"no host in url: {url}")
        if host not in [h.lower() for h in self.allowed_hosts]:
            raise ScopeError(f"host '{host}' is not in allowed_hosts; refusing")
        looks_prod = any(host.startswith(p) or p in host.split(".")[0] for p in PROD_HINTS)
        if looks_prod and host not in LOCAL_HOSTS and not self.allow_production:
            raise ScopeError(
                f"host '{host}' looks like production. Use a staging host, or set "
                "allow_production=true if you really own it and accept the risk."
            )


class ScopedHTTP:
    def __init__(self, scope: Scope, timeout: float = 10.0, verify_tls: bool = True):
        self.scope = scope
        self.timeout = timeout
        self.last_set_cookies: list[str] = []
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method: str, url: str, headers: dict | None = None,
                body: dict | bytes | None = None) -> tuple[int, dict, str]:
        self.scope.check(url)
        data = None
        hdrs = {"User-Agent": "guard/0.1 (self-owned security test)"}
        hdrs.update(headers or {})
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            data = body
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        self.last_set_cookies = []
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                self.last_set_cookies = r.headers.get_all("Set-Cookie") or []
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(200_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            self.last_set_cookies = e.headers.get_all("Set-Cookie") or []
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(200_000).decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError) as e:
            return 0, {}, f"request failed: {e}"
