"""`guard doctor --explain <check>`: what a check does, what it needs, whether it writes data, and an example."""
from __future__ import annotations

# name -> (what it does, needs, writes data?, example config)
DOCS: dict[str, tuple[str, list[str], bool, str]] = {
    "tenant": (
        "Cross-tenant test. For each resource tenant A owns, requests it as A (must work), with no login (must "
        "fail) and as tenant B (must fail). A 200 with an empty body counts as 'no data', not a leak.",
        ["tenant_a_token and tenant_b_token: two real test users from DIFFERENT tenants (two workspaces, studios, "
         "shops...). Tokens go in environment variables, written as \"ENV:NAME\".",
         "tenant_a_resources: paths of data tenant A owns that really contain something."],
        False,
        '"tenant_a_token": "ENV:TENANT_A_TOKEN", "tenant_b_token": "ENV:TENANT_B_TOKEN",\n'
        '"tenant_a_resources": ["/api/clients/<an id tenant A owns>"]'),
    "tenant_routes": (
        "Goes further than `tenant`: reads your OpenAPI schema, finds every route that takes an id, and tries each "
        "one as tenant B against tenant A's ids, including file and signed-link routes. Write routes (PUT, PATCH, "
        "POST, DELETE) are only tried when you turn them on.",
        ["Everything `tenant` needs.", "An OpenAPI schema: openapi_path (default /openapi.json) or openapi_file.",
         "Write routes: tenant_write_checks=true, and ideally tenant_write_bodies with a valid body per route."],
        True,
        '"openapi_path": "/openapi.json", "tenant_a_ids": {"client_id": "<id>"}, "tenant_write_checks": false'),
    "access": (
        "Role rules. For apps whose users have roles (staff, client, admin) rather than tenants: each rule names a "
        "caller, a path and what must happen (denied, empty or allowed).",
        ["tokens: one named token per role, from environment variables.",
         "access_checks: the rules."],
        False,
        '"tokens": {"client": "ENV:CLIENT_TOKEN"},\n'
        '"access_checks": [{"name": "client cannot list staff", "path": "/api/staff", "caller": "client", "expect": "denied"}]'),
    "injection": (
        "Sends a single quote and a true/false pair to inputs and looks for database errors or response "
        "differences. Never destructive.",
        ["injection_params (query parameters) and/or injection_targets (filter syntax, JSON bodies, /rpc routes)."],
        False,
        '"injection_params": ["q"],\n"injection_targets": [{"path": "/rpc/search", "method": "POST", "body": {"q": "{payload}"}}]'),
    "mass_assignment": (
        "Sends privileged fields (role, is_admin, tenant_id, owner_id) to your own create/update routes and checks "
        "whether the server stored them.",
        ["mass_assignment_targets: the create/update routes to try."],
        True, '"mass_assignment_targets": [{"path": "/api/profile", "method": "PATCH", "body": {"name": "x"}}]'),
    "upload": (
        "Uploads harmless files with risky names and types (.php, .html, .svg with script) and flags the ones the "
        "server accepts.",
        ["upload_path and upload_field."], True, '"upload_path": "/api/upload", "upload_field": "file"'),
    "ratelimit": (
        "Sends rapid failed logins and checks that the server eventually answers 429.",
        ["rate_limit_path: your login route."], True, '"rate_limit_path": "/api/auth/login", "rate_limit_attempts": 30'),
    "headers": (
        "Security response headers, reported once per host. Page-only headers (CSP, framing) are only expected on "
        "HTML; HSTS is not expected on local plain http.",
        ["probe_paths."], False, '"probe_paths": ["/", "/api/health"]'),
    "cors": ("Whether a site you do not own may read responses, especially with credentials.",
             ["probe_paths."], False, ""),
    "cookies": ("Session cookies missing HttpOnly, Secure or SameSite.", ["probe_paths."], False, ""),
    "exposed": ("Public .env, .git, database dumps and debug pages, verified by content.", [], False, ""),
    "jwt": ("Tokens with no expiry or alg=none, and (live) whether the server accepts forged copies of your own token.",
            ["tenant_a_token."], False, ""),
    "ai": ("AI-app code problems (keys in the browser, model output reaching eval or raw HTML) and, live, "
           "prompt-injection leaks of canary strings.",
           ["Live part: ai_endpoint and ai_canaries."], False,
           '"ai_endpoint": {"path": "/api/chat", "method": "POST", "field": "message"}, "ai_canaries": ["<a secret string in your system prompt>"]'),
    "db_rules": ("Static: SQL tables without row-level security and policies that match every row.",
                 ["SQL migration files under source_dir."], False, ""),
    "db_access": ("Static: SECURITY DEFINER search_path, functions anyone can run, views without security_invoker, "
                  "grants beyond policies, public buckets and bucket size limits, service keys in client files.",
                  ["SQL migration files and front-end files under source_dir."], False, ""),
    "supabase_audit": (
        "Supabase / Postgres configuration audit, strictly read-only. Reads supabase/config.toml auth settings, "
        "imports a JSON export of Supabase's own advisors (which is where leaked-password protection shows up), and "
        "can read a live database's catalog with SELECT statements only.",
        ["Any of: supabase/config.toml; supabase_advisors_file; db_audit_url with db_audit_allowed_hosts and psql."],
        False,
        '"supabase_advisors_file": "advisors.json",\n"db_audit_url": "ENV:STAGING_DB_URL", "db_audit_allowed_hosts": ["db.<staging-ref>.supabase.co"]'),
    "prod_config": (
        "Static lint of env files and settings code for things that must not ship: demo or debug logins on, "
        "wildcard CORS, debug mode, default or short secrets, plain http or localhost URLs, missing security headers "
        "and rate limiting. Reads files only; never connects to anything.",
        ["Env files (.env.production and similar) and settings code under source_dir."], False, ""),
    "semgrep": ("Code-pattern scanner (outside tool).", ["semgrep installed: pip install semgrep (pin the version)."], False, ""),
    "gitleaks": ("Secret scanner (outside tool).", ["gitleaks installed; see `guard doctor --install` and scanners.lock."], False, ""),
    "trivy": ("Dependency vulnerability scanner (outside tool).", ["trivy installed; see `guard doctor --install` and scanners.lock."], False, ""),
}


def explain(name: str) -> str:
    key = name.strip().lower()
    if key not in DOCS:
        return f"Unknown check '{name}'. Known checks: {', '.join(sorted(DOCS))}"
    what, needs, writes, example = DOCS[key]
    lines = [f"{key}", "", what, "", "Needs:"] + [f"  - {n}" for n in (needs or ["nothing; it works without configuration"])]
    lines += ["", "Writes data to your app: " + ("YES. Use staging with dummy data only." if writes else "no (read-only)")]
    if example:
        lines += ["", "Example (guard.config.json):", *(f"  {x}" for x in example.splitlines())]
    return "\n".join(lines)
