"""Supabase / Postgres configuration audit. STRICTLY READ-ONLY: it never writes to, migrates or changes anything.

Three sources, each optional, each reported in the coverage table:

1. supabase/config.toml: weak auth settings (short minimum password, email confirmations off, anonymous sign-ins on,
   long-lived tokens, wildcard redirect URLs). This file configures the local stack and `supabase config push`;
   a hosted project's settings live in the dashboard.
2. `supabase_advisors_file`: a JSON export of Supabase's own advisors (security lints) that YOU save from the
   dashboard or the Supabase tools. Guard only reads the file. This is where hosted-only settings such as
   leaked-password protection appear, because they cannot be read from your code.
3. `db_audit_url` (+ `db_audit_allowed_hosts`): a live look at a database's catalog: RLS on every public table,
   policies, grants, SECURITY DEFINER functions, views, storage buckets. It needs the `psql` program, runs only when
   live checks are on, refuses hosts you have not listed and hosts that look like production, and sends a fixed set
   of SELECT statements inside a READ ONLY transaction. Use a read-only database role.

The checks reuse the same rules as db_rules and db_access, so a migration file and the live database are judged alike."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..coverage import Skipped
from ..files import walk
from ..findings import Finding
from ..scope import LOCAL_HOSTS, Scope, ScopeError
from . import db_access, db_rules

NOTE = ("This file configures the local stack and `supabase config push`. A hosted project's settings are changed "
        "in the Supabase dashboard.")


# ---- 1. config.toml ---------------------------------------------------------------------------------------------
def parse_toml(text: str) -> dict[str, dict]:
    """Just enough TOML for config.toml: [sections] and key = scalar. Values that are not bool/int/quoted strings
    are kept as their raw text. (Python 3.10 has no tomllib, and guard has no dependencies.)"""
    sections: dict[str, dict] = {"": {}}
    cur = ""
    for raw in text.splitlines():
        line, quote = [], ""
        for ch in raw:  # drop a trailing # comment that is not inside a string
            if quote:
                quote = "" if ch == quote else quote
            elif ch in "\"'":
                quote = ch
            elif ch == "#":
                break
            line.append(ch)
        line = "".join(line).strip()
        if not line:
            continue
        m = re.match(r"^\[\[?([^\]]+)\]\]?$", line)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, {})
        elif "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            if v.lower() in ("true", "false"):
                val: object = v.lower() == "true"
            elif re.fullmatch(r"-?\d+", v):
                val = int(v)
            elif len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                val = v[1:-1]
            else:
                val = v
            sections[cur][k] = val
    return sections


def config_findings(path: str, text: str) -> list[Finding]:
    t = parse_toml(text)
    auth, email = t.get("auth", {}), t.get("auth.email", {})
    out: list[Finding] = []

    def add(sev, title, detail, fix):
        out.append(Finding("supabase_audit", sev, title, f"{detail} {NOTE}", path, fix=fix, tags=["supabase-config"]))

    n = auth.get("minimum_password_length")
    if isinstance(n, int) and n < 8:
        add("medium", f"Minimum password length is {n}", "Short passwords are easy to guess.",
            "Set minimum_password_length to at least 8 (12 is better).")
    if "password_requirements" in auth and auth["password_requirements"] == "":
        add("low", "No password complexity requirements", "password_requirements is empty.",
            "Require letters and digits (or more) in password_requirements.")
    if email.get("enable_confirmations") is False:
        add("medium", "Email confirmation is off", "Anyone can sign up with an address they do not own.",
            "Set [auth.email] enable_confirmations = true.")
    if auth.get("enable_anonymous_sign_ins") is True:
        add("medium", "Anonymous sign-ins are on",
            "Anonymous users get the `authenticated` role, so any policy written `TO authenticated` applies to them.",
            "Turn it off unless you need it, and review every `TO authenticated` policy.")
    jwt = auth.get("jwt_expiry")
    if isinstance(jwt, int) and jwt > 3600:
        add("medium" if jwt > 86400 else "low", f"Access tokens last {jwt} seconds",
            "A stolen token stays valid for that long.", "Keep jwt_expiry at 3600 or less and rely on refresh tokens.")
    if auth.get("enable_refresh_token_rotation") is False:
        add("low", "Refresh token rotation is off", "A stolen refresh token can be reused indefinitely.",
            "Set enable_refresh_token_rotation = true.")
    if email.get("secure_password_change") is False:
        add("low", "Password change does not require recent sign-in", "secure_password_change is false.",
            "Set [auth.email] secure_password_change = true.")
    if email.get("double_confirm_changes") is False:
        add("low", "Email change needs no double confirmation", "double_confirm_changes is false.",
            "Set [auth.email] double_confirm_changes = true.")
    raw = str(auth.get("additional_redirect_urls", ""))
    if re.search(r"\"https?://\*|\"\*\"", raw):
        add("medium", "Wildcard redirect URL allowed", "A wildcard redirect lets an attacker send users to a look-alike site.",
            "List the exact redirect URLs you use.")
    return out


# ---- 2. Supabase advisors export --------------------------------------------------------------------------------
LEVEL = {"ERROR": "high", "WARN": "medium", "WARNING": "medium", "INFO": "low"}


def _lints(data) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("lints", "advisors", "result", "results", "data"):
            if key in data:
                return _lints(data[key])
    return []


def advisor_findings(path: str, text: str) -> list[Finding]:
    """Findings from an export of Supabase's advisors. Parsed defensively: unknown shapes give no findings."""
    try:
        lints = _lints(json.loads(text))
    except ValueError as e:
        raise ValueError(f"{path} is not valid JSON") from e
    out: list[Finding] = []
    for lint in lints:
        name = str(lint.get("name", "advisor"))
        meta = lint.get("metadata") if isinstance(lint.get("metadata"), dict) else {}
        where = ".".join(str(meta[k]) for k in ("schema", "name") if meta.get(k)) or str(lint.get("facing", ""))
        sev = LEVEL.get(str(lint.get("level", "")).upper(), "low")
        detail = " ".join(str(lint.get(k, "")).strip() for k in ("description", "detail") if lint.get(k))[:600]
        out.append(Finding("supabase_audit", sev, f"Supabase advisor: {lint.get('title') or name}"
                           + (f" ({where})" if where else ""), detail or name, path,
                           fix=str(lint.get("remediation", "")), tags=["supabase-advisor", name]))
    return out


# ---- 3. live catalog (read-only) --------------------------------------------------------------------------------
QUERIES = {
    "tables": "select c.relname, c.relrowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace "
              "where n.nspname = 'public' and c.relkind in ('r', 'p')",
    "policies": "select schemaname, tablename, policyname, cmd, array_to_string(roles, ',') as roles, qual, with_check "
                "from pg_policies where schemaname in ('public', 'storage')",
    "grants": "select c.relname as table_name, case when a.grantee = 0 then 'public' else pg_get_userbyid(a.grantee) end "
              "as grantee, a.privilege_type from pg_class c join pg_namespace n on n.oid = c.relnamespace, "
              "lateral aclexplode(c.relacl) a where n.nspname = 'public' and c.relkind in ('r', 'p', 'v')",
    "functions": "select p.proname, p.prosecdef, coalesce(array_to_string(p.proconfig, ','), '') as config, "
                 "p.prorettype::regtype::text as returns, (to_regrole('anon') is not null and "
                 "has_function_privilege('anon', p.oid, 'execute')) as anon_exec from pg_proc p "
                 "join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind in ('f', 'p') "
                 "and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')",
    "views": "select c.relname, coalesce(array_to_string(c.reloptions, ','), '') as options from pg_class c "
             "join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'v'",
    "has_storage": "select (to_regclass('storage.buckets') is not null) as present",
    "buckets": "select id, public, file_size_limit from storage.buckets",
}
_SELECT_ONLY = re.compile(r"^\s*select\b", re.I)


def assert_read_only(sql: str) -> str:
    """Refuse anything that is not a single SELECT. Belt and braces: the session is also READ ONLY."""
    body = sql.strip().rstrip(";")
    if not _SELECT_ONLY.match(body) or ";" in body:
        raise ValueError("guard only sends a single SELECT to a database")
    return body


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("t", "true", "1")


def psql_rows(url: str, sql: str, run=subprocess.run) -> list[dict]:
    """Run one SELECT through psql inside a READ ONLY transaction and return its rows."""
    body = assert_read_only(sql)
    u = urlparse(url)
    host = (u.hostname or "").lower()
    q = parse_qs(u.query)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "PGCONNECT_TIMEOUT": "10",
           "PGHOST": host, "PGPORT": str(u.port or 5432), "PGUSER": unquote(u.username or ""),
           "PGDATABASE": (u.path or "/postgres").lstrip("/") or "postgres",
           "PGSSLMODE": (q.get("sslmode") or ["prefer" if host in LOCAL_HOSTS else "require"])[0]}
    if u.password:
        env["PGPASSWORD"] = unquote(u.password)  # via the environment, so it never appears in a process list
    script = f"BEGIN READ ONLY;\nSET LOCAL statement_timeout = '15s';\n{body};\nROLLBACK;\n"
    try:
        p = run(["psql", "-X", "-q", "--csv", "-v", "ON_ERROR_STOP=1"], input=script, capture_output=True, text=True,
                timeout=60, env=env)
    except (subprocess.TimeoutExpired, OSError):
        raise RuntimeError("psql could not run the query (timed out, or the psql program could not be started)") from None
    if p.returncode != 0:
        raise RuntimeError("psql could not run the query (check the connection string, role and network)")
    return list(csv.DictReader(io.StringIO(p.stdout)))


def check_target(cfg) -> str:
    """The database host, after the scope guard has approved it (raises ScopeError otherwise)."""
    host = (urlparse(cfg.db_audit_url).hostname or "").lower()
    if not host:
        raise ScopeError("db_audit_url has no host")
    try:
        Scope(cfg.db_audit_allowed_hosts, cfg.allow_production).check(f"postgresql://{host}/")
    except ScopeError as e:
        raise ScopeError(str(e).replace("allowed_hosts", "db_audit_allowed_hosts")) from None
    return host


def live_findings(host: str, fetch) -> list[Finding]:
    """Judge a live catalog. `fetch(name) -> rows` runs one of QUERIES."""
    where = f"live database {host}"
    out: list[Finding] = []
    tables = fetch("tables")
    enabled = {r["relname"] for r in tables if _truthy(r["relrowsecurity"])}
    for r in tables:
        if r["relname"] not in enabled:
            out.append(Finding("supabase_audit", "high", f"Table '{r['relname']}' has no row-level security (live database)",
                               "Anyone who can reach the database API may read or write all rows.", where,
                               fix=f"ALTER TABLE {r['relname']} ENABLE ROW LEVEL SECURITY; then add policies. "
                                   + db_rules.ACCEPT_HINT, tags=["owasp-a01"]))
    pols: dict[str, list[dict]] = {}
    for r in fetch("policies"):
        qual, chk = (r.get("qual") or "").strip().lower(), (r.get("with_check") or "").strip().lower()
        schema = r["schemaname"]
        pol = {"name": r["policyname"], "table": f"{schema}.{r['tablename']}",
               "cmd": r["cmd"].lower(), "roles": {x.strip().lower() for x in r["roles"].split(",") if x.strip()} or {"public"},
               "using_true": qual in ("true", "(true)"), "check_true": chk in ("true", "(true)")}
        if schema == "public":
            pols.setdefault(r["tablename"], []).append(pol)
        f = db_rules._policy_finding(where, pol)
        if f:
            f.title += " (live database)"
            out.append(f)
        if schema == "storage" and r["tablename"] == "objects" and "bucket_id" not in (qual + chk):
            out.append(Finding("supabase_audit", "medium", f"Storage policy '{r['policyname']}' is not limited to one bucket (live database)",
                               "A policy on storage.objects without a bucket_id condition applies to every bucket, including "
                               "ones added later.", where, fix="Add bucket_id = '<name>' to USING and WITH CHECK. " + db_access.ACCEPT,
                               tags=["owasp-a01"]))
    grants = [(where, r["table_name"], r["grantee"].lower(), {r["privilege_type"].lower()}) for r in fetch("grants")
              if r["grantee"].lower() in ("anon", "authenticated", "public")]
    for f in db_access.grant_gaps(grants, pols, enabled):
        f.title += " (live database)"
        out.append(f)
    for r in fetch("functions"):
        name, definer = r["proname"], _truthy(r["prosecdef"])
        if r["returns"] == "trigger":
            continue
        if definer and "search_path=" not in r["config"].replace(" ", ""):
            out.append(Finding("supabase_audit", "high", f"SECURITY DEFINER function '{name}' has no fixed search_path (live database)",
                               "It runs with its owner's rights and a caller can plant look-alike objects.", where,
                               fix="Add SET search_path = '' to the function.", tags=["owasp-a01"]))
        if _truthy(r["anon_exec"]):
            out.append(Finding("supabase_audit", "high" if definer else "low", f"Function '{name}' can be run by anonymous callers (live database)",
                               "EXECUTE is granted to anon (directly or through PUBLIC)" +
                               (" and the function runs with its owner's rights." if definer else "."), where,
                               fix=f"REVOKE EXECUTE ON FUNCTION {name}(...) FROM PUBLIC, anon. " + db_access.ACCEPT,
                               tags=["owasp-a01"]))
    granted = {g[1] for g in grants}
    for r in fetch("views"):
        if "security_invoker=true" in r["options"].replace(" ", "").lower() or "security_invoker=on" in r["options"].replace(" ", "").lower():
            continue
        out.append(Finding("supabase_audit", "high" if r["relname"] in granted else "medium",
                           f"View '{r['relname']}' is not security_invoker (live database)",
                           "A view runs with its owner's rights, so it skips row-level security on the tables underneath.", where,
                           fix="Recreate it WITH (security_invoker = true). " + db_access.ACCEPT, tags=["owasp-a01"]))
    present = fetch("has_storage")
    if present and _truthy(present[0]["present"]):
        for r in fetch("buckets"):
            if _truthy(r["public"]):
                out.append(Finding("supabase_audit", "medium", f"Storage bucket '{r['id']}' is public (live database)",
                                   "Anyone with a file's URL can read it without signing in.", where,
                                   fix="Make it private and use signed URLs. " + db_access.ACCEPT, tags=["owasp-a01"]))
            if not (r.get("file_size_limit") or "").strip():
                out.append(Finding("supabase_audit", "low", f"Storage bucket '{r['id']}' has no file size limit (live database)",
                                   "Without a limit one user can upload very large files.", where,
                                   fix="Set file_size_limit on the bucket. " + db_access.ACCEPT))
    return out


# ---- the check --------------------------------------------------------------------------------------------------
def _note(title: str) -> Finding:
    return Finding("supabase_audit", "info", title, "", tags=["coverage-note"])


def run(cfg, http, psql=psql_rows) -> list[Finding]:
    findings: list[Finding] = []
    ran: list[str] = []
    notes: list[Finding] = []
    toml = [p for p in walk(cfg.source_dir, (".toml",)) if p.name == "config.toml" and "supabase" in {x.lower() for x in p.parts}]
    for p in toml:
        findings += config_findings(str(p), p.read_text(errors="replace"))
    if toml:
        ran.append("config.toml")
    if cfg.supabase_advisors_file:
        path = Path(cfg.supabase_advisors_file)
        if not path.is_absolute():
            path = Path(cfg.source_dir) / path
        try:
            findings += advisor_findings(str(path), path.read_text(errors="replace"))
            ran.append("advisors export")
        except (OSError, ValueError):
            notes.append(_note(f"advisors file {cfg.supabase_advisors_file} could not be read as JSON"))
    supabase_project = bool(toml) or any("supabase" in {x.lower() for x in p.parts}
                                         for p in walk(cfg.source_dir, (".sql",), all_files=True))
    if cfg.supabase_advisors_file == "" and supabase_project:
        notes.append(_note("advisors export not provided (supabase_advisors_file): leaked-password protection and "
                           "other hosted-only settings were not checked"))
    if cfg.db_audit_url:
        if http is None:
            notes.append(_note("live database audit is off (live checks are off)"))
        else:
            host = check_target(cfg)  # ScopeError propagates: exit 3, nothing sent
            if not shutil.which("psql"):
                notes.append(_note("live database audit needs the psql program, which is not installed"))
            else:
                try:
                    cache: dict[str, list[dict]] = {}

                    def fetch(name):
                        if name not in cache:
                            cache[name] = psql(cfg.db_audit_url, QUERIES[name])
                        return cache[name]
                    findings += live_findings(host, fetch)
                    ran.append("live catalog")
                except (RuntimeError, KeyError, ValueError) as e:
                    notes.append(_note(f"live database audit failed: {e}"))
    elif supabase_project:
        notes.append(_note("live catalog audit not configured (db_audit_url, db_audit_allowed_hosts)"))
    if not ran and not supabase_project and not notes:
        raise Skipped("no supabase/config.toml, supabase_advisors_file or db_audit_url", applicable=False)
    if not ran:
        raise Skipped("nothing could be read: " + "; ".join(n.title for n in notes))
    findings += notes
    if ran:
        findings.append(_note("read: " + ", ".join(ran)))
    return findings
