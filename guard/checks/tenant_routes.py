"""Cross-tenant test across every id-bearing route in your OpenAPI schema.

`tenant` tries the resource URLs you list. This check goes further: it reads the schema, learns tenant A's ids from
the resources you listed (and `tenant_a_ids`), and tries EVERY route that takes those ids as tenant B (and, for
reads, with no login), including file and signed-link routes:

  reads (GET)      always. 2xx with data is a leak; 2xx with an empty body is correct row-level-security behavior.
  writes           only when `tenant_write_checks` is true. PUT, PATCH and POST first, DELETE last. If isolation is
                   broken a write can CHANGE OR DELETE tenant A's data, so use disposable staging data. A 400/422
                   means the body was rejected before access was checked, which proves nothing: supply a valid body
                   in `tenant_write_bodies` (key "PATCH /clients/{client_id}").

Needs tenant_a_token, tenant_b_token, tenant_a_resources, and the schema (openapi_path or openapi_file)."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from .. import openapi
from ..bodies import is_empty_body
from ..coverage import Skipped
from ..findings import Finding

OK = range(200, 300)
MAX_ROUTES = 200
WRITE_ORDER = {"PUT": 0, "PATCH": 1, "POST": 2, "DELETE": 3}  # DELETE last, so a destructive hit cannot hide the rest


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def learn_ids(ops: list[openapi.Op], resources: list[str], given: dict) -> tuple[dict, str]:
    """Tenant A's ids by parameter name (from the resource URLs and `tenant_a_ids`) and the URL prefix they share."""
    ids, prefix = dict(given), None
    for res in resources:
        for op in ops:
            hit = openapi.match_template(op.template, res)
            if hit:
                prefix = hit[0] if prefix is None else prefix
                for k, v in hit[1].items():
                    ids.setdefault(k, v)
    return ids, prefix or ""


def fill(template: str, ids: dict) -> str:
    out = template
    for k, v in ids.items():
        out = out.replace("{" + k + "}", quote(str(v), safe=""))
    return out


def evaluate_read(op: openapi.Op, url: str, a_status: int, a_body: str, b_status: int, b_body: str,
                  anon_status: int, anon_body: str) -> list[Finding]:
    kind = "file or signed-link route" if op.file_like else "route"
    out: list[Finding] = []
    if a_status not in OK or (not op.file_like and is_empty_body(a_body)):
        return [Finding("tenant_routes", "info", f"Inconclusive: {op.key}",
                        f"Tenant A got {a_status}" + (" with no data" if a_status in OK else "") +
                        ", so tenant B's result proves nothing for this route.", url)]
    if anon_status in OK and not is_empty_body(anon_body):
        out.append(Finding("tenant_routes", "critical", f"{op.key} readable without authentication",
                           f"An unauthenticated request to this {kind} returned data.", url,
                           evidence=f"anon status={anon_status}", fix="Require auth on this route.", tags=["owasp-a01"]))
    if b_status in OK:
        if is_empty_body(b_body):
            out.append(Finding("tenant_routes", "info", f"{op.key}: other tenant got 200 with an empty body",
                               "No data was returned, which is correct row-level-security behavior.", url))
        else:
            out.append(Finding("tenant_routes", "critical", f"Cross-tenant data access on {op.key}",
                               f"Tenant B read tenant A's data through this {kind}.", url,
                               evidence=f"tenant B status={b_status}, body[:80]={b_body[:80]!r}",
                               fix="Scope every query by the caller's tenant id on the server and enforce row-level "
                                   "security in the database.", tags=["owasp-a01"]))
    return out


def evaluate_write(op: openapi.Op, url: str, b_status: int) -> list[Finding]:
    if b_status in OK:
        return [Finding("tenant_routes", "critical", f"Tenant B changed tenant A's data via {op.key}",
                        f"{op.method} as tenant B succeeded on tenant A's id. Tenant A's data may now be changed or "
                        "deleted: restore your staging data.", url, evidence=f"tenant B status={b_status}",
                        fix="Check ownership on the server before every write, and enforce row-level security.",
                        tags=["owasp-a01"])]
    if b_status in (400, 422):
        return [Finding("tenant_routes", "info", f"Inconclusive: {op.key} rejected the body first",
                        "The route validated the request body before checking access, so this proves nothing. "
                        "Add a valid body under tenant_write_bodies.", url, evidence=f"status={b_status}")]
    if b_status >= 500:
        return [Finding("tenant_routes", "medium", f"{op.key} returned a server error for another tenant",
                        "A foreign id made the server fail instead of refusing cleanly.", url,
                        evidence=f"status={b_status}", fix="Return 403/404 for ids the caller does not own.")]
    if b_status == 0:
        return [Finding("tenant_routes", "info", f"Inconclusive: {op.key} got no answer", "The request failed.", url)]
    return []


def run(cfg, http) -> list[Finding]:
    missing = [n for n, v in (("tenant_a_token", cfg.tenant_a_token), ("tenant_b_token", cfg.tenant_b_token),
                              ("tenant_a_resources", cfg.tenant_a_resources)) if not v]
    if missing:
        raise Skipped("not set: " + ", ".join(missing))
    if cfg.tenant_a_token == cfg.tenant_b_token:
        raise Skipped("tenant_a_token and tenant_b_token are the same token, so there is no 'other tenant' to test")
    base = cfg.base_url.rstrip("/")
    a_h, b_h = _headers(cfg.tenant_a_token), _headers(cfg.tenant_b_token)
    try:
        if cfg.openapi_file:
            path = Path(cfg.openapi_file)
            text = (path if path.is_absolute() else Path(cfg.source_dir) / path).read_text()
        else:
            status, _, text = http.request("GET", base + cfg.openapi_path, a_h)
            if status not in OK:
                raise Skipped(f"could not read the OpenAPI schema at {cfg.openapi_path} (status {status}); "
                              "set openapi_path or openapi_file")
        spec = openapi.parse(text)
    except Skipped:
        raise
    except (OSError, ValueError):
        raise Skipped("the OpenAPI schema could not be read (openapi_path / openapi_file)") from None
    ops = openapi.operations(spec)
    if not ops:
        raise Skipped("the OpenAPI schema has no routes that take an id")
    ids, prefix = learn_ids(ops, cfg.tenant_a_resources, cfg.tenant_a_ids)
    prefix = prefix or openapi.server_prefix(spec)
    usable = [o for o in ops if all(p in ids for p in o.params)]
    unknown = sorted({p for o in ops for p in o.params if p not in ids})
    reads = [o for o in usable if o.method == "GET"]
    writes = sorted((o for o in usable if o.method in WRITE_ORDER), key=lambda o: WRITE_ORDER[o.method]) \
        if cfg.tenant_write_checks else []
    skipped_writes = sum(1 for o in usable if o.method in WRITE_ORDER) if not cfg.tenant_write_checks else 0
    truncated = max(0, len(reads) + len(writes) - MAX_ROUTES)
    reads, writes = reads[:MAX_ROUTES], writes[:max(0, MAX_ROUTES - len(reads))]
    findings: list[Finding] = []
    for op in reads:
        url = base + prefix + fill(op.template, ids)
        a_s, _, a_b = http.request("GET", url, a_h)
        b_s, _, b_b = http.request("GET", url, b_h)
        an_s, _, an_b = http.request("GET", url)
        findings += evaluate_read(op, url, a_s, a_b, b_s, b_b, an_s, an_b)
    for op in writes:
        url = base + prefix + fill(op.template, ids)
        body = cfg.tenant_write_bodies.get(op.key, {} if op.method != "DELETE" else None)
        b_s, _, _ = http.request(op.method, url, b_h, body)
        findings += evaluate_write(op, url, b_s)
    note = f"tested {len(reads)} read and {len(writes)} write route(s) as tenant B"
    if skipped_writes:
        note += f"; {skipped_writes} write route(s) NOT tried (tenant_write_checks is off)"
    if unknown:
        note += f"; routes needing ids you did not give were skipped ({', '.join(unknown[:6])}); add them to tenant_a_ids"
    if truncated:
        note += f"; {truncated} route(s) over the {MAX_ROUTES} limit were not tried"
    findings.append(Finding("tenant_routes", "info", note, "", tags=["coverage-note"]))
    return findings
