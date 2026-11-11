from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .accept import validate as validate_accepted


def resolve_secret(val):
    """`"ENV:NAME"` reads the environment variable NAME; anything else is used as written."""
    if isinstance(val, str) and val.startswith("ENV:"):
        return os.environ.get(val[4:], "")
    return val

# Hosts that are obviously placeholders. A live scan against one is refused (and `guard init` writes one).
PLACEHOLDER_SUFFIXES = (".example", ".invalid", ".test")

# Written by `guard init`. Kept in code so it works after a normal pip install.
DEFAULT_CONFIG: dict = {
    # guard init writes made-up hosts and routes. Live scans are refused until you review them and set this true.
    "setup_complete": False,
    "base_url": "https://staging.yourapp.example",
    "allowed_hosts": ["staging.yourapp.example"],
    "allow_production": False,
    "source_dir": ".",
    "tenant_a_token": "ENV:TENANT_A_TOKEN",
    "tenant_b_token": "ENV:TENANT_B_TOKEN",
    "tenant_a_resources": ["/api/items/123", "/api/orders/456"],
    "probe_paths": ["/", "/api/health", "/api/items"],
    "injection_params": ["q", "search", "id"],
    "rate_limit_path": "/api/auth/login",
    "rate_limit_attempts": 30,
    "mass_assignment_targets": [
        {"path": "/api/profile", "method": "PATCH", "body": {"name": "guard-test"}}
    ],
    "upload_path": "",
    "upload_field": "file",
    "ai_endpoint": {},
    "ai_canaries": [],
    "accepted_risks": [],
    "max_fix_rounds": 5,
    "fail_on": "high",
}


@dataclass
class Config:
    # False only in a fresh `guard init` file. Older configs without the key keep working.
    setup_complete: bool = True
    base_url: str = ""
    allowed_hosts: list[str] = field(default_factory=list)
    allow_production: bool = False
    source_dir: str = "."
    # Two users from DIFFERENT tenants (workspaces, orgs, accounts) for isolation tests.
    tenant_a_token: str = ""
    tenant_b_token: str = ""
    # Resource URLs owned by tenant A. Tenant B must NOT be able to read them.
    tenant_a_resources: list[str] = field(default_factory=list)
    # Named tokens for roles other than the two tenants, e.g. {"staff": "ENV:STAFF_TOKEN", "client": "ENV:CLIENT_TOKEN"}.
    tokens: dict = field(default_factory=dict)
    # Which token each check uses: {"injection": "client", "upload": "staff", "mass_assignment": "anonymous"}.
    # A value is a name from `tokens`, "tenant_a", "tenant_b" or "anonymous" (send no token). Default: tenant A.
    check_tokens: dict = field(default_factory=dict)
    # Role-based access rules, for apps with roles instead of two tenants. Each:
    # {"name": "client cannot list staff", "path": "/api/staff", "method": "GET",
    #  "caller": "anonymous" | <token name>, "expect": "denied" | "empty" | "allowed"}
    access_checks: list[dict] = field(default_factory=list)
    # Authenticated endpoints to probe (paths, GET).
    probe_paths: list[str] = field(default_factory=lambda: ["/"])
    # Header, CORS, cookie and injection checks look at the first N probe paths (the rest are reported as unchecked).
    max_probe_paths: int = 5
    # Query params to test for injection on probe_paths.
    injection_params: list[str] = field(default_factory=list)
    # Injection inputs that are not plain query parameters. Each: {"path", "method", "body", "token"} where the
    # string "{payload}" inside path or body is replaced. Examples:
    #   {"path": "/rest/v1/items?name=eq.{payload}"}
    #   {"path": "/rpc/search", "method": "POST", "body": {"q": "{payload}"}}
    injection_targets: list[dict] = field(default_factory=list)
    rate_limit_path: str = ""
    rate_limit_attempts: int = 30
    # Endpoints that create/update records, to test for mass assignment.
    # Each: {"path": "/api/profile", "method": "PATCH", "body": {"name": "x"}}
    mass_assignment_targets: list[dict] = field(default_factory=list)
    # File upload endpoint (multipart) and its form field name.
    upload_path: str = ""
    upload_field: str = "file"
    # LLM-backed endpoint: {"path": "/api/chat", "method": "POST", "field": "message"}
    ai_endpoint: dict = field(default_factory=dict)
    # Secret strings you put in your system prompt as tripwires; they must never be echoed.
    ai_canaries: list[str] = field(default_factory=list)
    # Findings you have looked at and accepted: [{"check", "title" and/or "target" (* allowed), "reason", "owner",
    # "expires" (YYYY-MM-DD, optional)}]. They stop blocking but are always listed in the reports.
    accepted_risks: list[dict] = field(default_factory=list)
    # How many fix rounds the auto-fix loop may run before it stops and reports.
    max_fix_rounds: int = 5
    fail_on: str = "high"

    @classmethod
    def load(cls, path: str) -> "Config":
        raw = json.loads(Path(path).read_text())
        known = cls.__dataclass_fields__.keys()
        unknown = set(raw) - set(known)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        for key in ("tenant_a_token", "tenant_b_token"):
            if key in raw:
                raw[key] = resolve_secret(raw[key])
        if isinstance(raw.get("tokens"), dict):
            raw["tokens"] = {k: resolve_secret(v) for k, v in raw["tokens"].items()}
        raw["accepted_risks"] = validate_accepted(raw.get("accepted_risks", []))
        cfg = cls(**raw)
        cfg.check_config()
        return cfg

    def check_config(self) -> None:
        """Raise ValueError for settings that are present but wrong, so a typo is not silently ignored."""
        if self.max_probe_paths < 1:
            raise ValueError("max_probe_paths must be at least 1")
        names = {"anonymous", "tenant_a", "tenant_b", *self.tokens}
        for check, name in self.check_tokens.items():
            if name not in names:
                raise ValueError(f"check_tokens['{check}'] names unknown token '{name}'; "
                                 f"use one of {sorted(names)}")
        for n, a in enumerate(self.access_checks, 1):
            if not isinstance(a, dict) or not a.get("path"):
                raise ValueError(f"access_checks[{n}] needs a 'path'")
            if a.get("expect") not in ("denied", "empty", "allowed"):
                raise ValueError(f"access_checks[{n}] 'expect' must be denied, empty or allowed")
            if a.get("caller", "anonymous") not in names:
                raise ValueError(f"access_checks[{n}] caller '{a.get('caller')}' is not a known token name")
        for n, t in enumerate(self.injection_targets, 1):
            if not isinstance(t, dict) or "{payload}" not in json.dumps(t):
                raise ValueError(f"injection_targets[{n}] must contain the text {{payload}} in its path or body")

    def token(self, name: str) -> str | None:
        """The token for a name, "" for anonymous, or None when it is named but not set."""
        if name == "anonymous":
            return ""
        value = {"tenant_a": self.tenant_a_token, "tenant_b": self.tenant_b_token}.get(name, self.tokens.get(name, ""))
        return value or None

    def auth_headers(self, check: str):
        """Headers for a check. Honors check_tokens; defaults to tenant A when it is set, else no auth.
        Returns None when the check was told to use a token that is not set (the caller should skip)."""
        name = self.check_tokens.get(check)
        if name is None:
            return {"Authorization": f"Bearer {self.tenant_a_token}"} if self.tenant_a_token else {}
        tok = self.token(name)
        if tok is None:
            return None
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def probe_slice(self) -> list[str]:
        return self.probe_paths[: self.max_probe_paths]

    def live_blocker(self) -> str:
        """Why a live scan must not run yet, or "" when it may."""
        if not self.setup_complete:
            return ("guard.config.json is not marked as set up. Review base_url, allowed_hosts, tokens and routes "
                    '(they may still be the made-up values from `guard init`), then set "setup_complete": true.')
        host = (urlparse(self.base_url).hostname or "").lower()
        if not host:
            return "base_url is empty or has no host."
        if host.endswith(PLACEHOLDER_SUFFIXES):
            return f"base_url host '{host}' is still a placeholder. Point it at your real staging host."
        return ""
