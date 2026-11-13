"""Reading an OpenAPI schema: which routes take an id, and how to match a known URL to a route template."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

METHODS = ("get", "put", "patch", "post", "delete")
FILE_HINT = re.compile(r"photo|file|media|download|signed|attachment|document|image|export|avatar|upload|receipt|invoice", re.I)
PARAM = re.compile(r"\{([^}/]+)\}")


@dataclass
class Op:
    method: str            # GET, PATCH...
    template: str          # /clients/{client_id}/photos
    params: list[str] = field(default_factory=list)
    file_like: bool = False

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"


def parse(text: str) -> dict:
    spec = json.loads(text)
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("not an OpenAPI schema (no paths)")
    return spec


def _non_json_response(op: dict) -> bool:
    for resp in (op.get("responses") or {}).values():
        content = (resp or {}).get("content") or {}
        for ctype, body in content.items():
            fmt = ((body or {}).get("schema") or {}).get("format")
            if not ctype.lower().startswith(("application/json", "text/plain")) or fmt == "binary":
                return True
    return False


def operations(spec: dict) -> list[Op]:
    """Every operation whose path has at least one {parameter}."""
    ops: list[Op] = []
    for template, item in spec["paths"].items():
        params = PARAM.findall(template)
        if not params or not isinstance(item, dict):
            continue
        for m in METHODS:
            op = item.get(m)
            if isinstance(op, dict):
                ops.append(Op(m.upper(), template, params,
                              bool(FILE_HINT.search(template)) or _non_json_response(op)))
    return ops


def server_prefix(spec: dict) -> str:
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        path = urlparse(str(servers[0].get("url", ""))).path.rstrip("/")
        return path
    return ""


def match_template(template: str, concrete: str) -> tuple[str, dict] | None:
    """If `concrete` is an instance of `template`, return (path prefix before it, {param: value}).
    '/api/clients/abc' against '/clients/{client_id}' gives ('/api', {'client_id': 'abc'})."""
    path = urlparse(concrete).path
    # re.escape turns {x} into \{x\}; undo that, then swap each {x} for a capture group
    rx = "^(.*?)" + re.sub(r"\\?\{[^}/]+\\?\}", "([^/]+)", re.escape(template).replace("\\{", "{").replace("\\}", "}")) + "$"
    m = re.match(rx, path)
    if not m:
        return None
    return m.group(1), dict(zip(PARAM.findall(template), m.groups()[1:]))
