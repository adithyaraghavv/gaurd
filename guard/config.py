from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# Written by `guard init`. Kept in code so it works after a normal pip install.
DEFAULT_CONFIG: dict = {
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
    "max_fix_rounds": 5,
    "fail_on": "high",
}


@dataclass
class Config:
    base_url: str = ""
    allowed_hosts: list[str] = field(default_factory=list)
    allow_production: bool = False
    source_dir: str = "."
    # Two users from DIFFERENT tenants (workspaces, orgs, accounts) for isolation tests.
    tenant_a_token: str = ""
    tenant_b_token: str = ""
    # Resource URLs owned by tenant A. Tenant B must NOT be able to read them.
    tenant_a_resources: list[str] = field(default_factory=list)
    # Authenticated endpoints to probe (paths, GET).
    probe_paths: list[str] = field(default_factory=lambda: ["/"])
    # Query params to test for injection on probe_paths.
    injection_params: list[str] = field(default_factory=list)
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
            val = raw.get(key, "")
            if isinstance(val, str) and val.startswith("ENV:"):
                raw[key] = os.environ.get(val[4:], "")
        return cls(**raw)
