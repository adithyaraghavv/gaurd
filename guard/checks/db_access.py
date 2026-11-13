"""More static checks on SQL migrations and client-side files (Postgres/Supabase).

1. SECURITY DEFINER functions without a fixed search_path (a caller can plant a look-alike object and borrow the
   function owner's rights).
2. Functions anyone can run: Postgres grants EXECUTE to PUBLIC unless revoked, and on Supabase every function in
   an exposed schema is callable over the API.
3. Views created without `security_invoker`: they run with the view owner's rights and so skip the row-level
   security of the tables underneath.
4. Table grants to anon/authenticated that no policy backs up. Harmless while RLS stays on, but one forgotten
   ALTER TABLE away from exposure.
5. Storage: public buckets, and policies on storage.objects that are not limited to one bucket.
6. A privileged (service-role) key in front-end files, where every visitor can read it.

Reading order is not simulated: a revoke anywhere in the migrations counts as covering a function."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from ..coverage import Skipped
from ..files import is_changed, walk
from ..findings import Finding
from ..sqlscan import bare, ident, split_statements, split_top_level
from . import db_rules

NAME = r'(?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?'
FUNC = re.compile(rf"create\s+(?:or\s+replace\s+)?function\s+({NAME})\s*\(", re.I)
VIEW = re.compile(rf"create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+|recursive\s+)*view\s+({NAME})", re.I)
GRANT = re.compile(r"grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+?)(?:\s+with\s+grant\s+option)?$", re.I | re.S)
REVOKE = re.compile(r"revoke\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(.+?)\s+from\s+(.+?)(?:\s+(?:cascade|restrict))?$",
                    re.I | re.S)
WRITES = {"insert", "update", "delete", "truncate"}
# GRANT/REVOKE targets that are not tables
NON_TABLE = re.compile(r"(function|routine|procedure|sequence|schema|database|type|domain|language|"
                       r"all\s+(functions|routines|procedures|sequences)|foreign|large|tablespace)\b", re.I)
ACCEPT = "If this is intended, record it under accepted_risks in guard.config.json with a reason and an owner."


def _roles(text: str) -> set[str]:
    return {ident(r) for r in split_top_level(text)}


def _privs(text: str) -> set[str]:
    out: set[str] = set()
    for p in split_top_level(re.sub(r"\([^)]*\)", "", text)):  # drop column lists
        p = p.lower().replace("privileges", "").strip()
        out |= {"select", "insert", "update", "delete", "truncate", "references", "trigger"} if p == "all" else {p}
    return out


# ---- functions -------------------------------------------------------------------------------------------------
def _functions(stmts: list[tuple[str, str]]) -> list[dict]:
    out = []
    for path, st in stmts:
        m = FUNC.match(st)
        if not m:
            continue
        out.append({
            "path": path, "name": bare(m.group(1)),
            "definer": bool(re.search(r"\bsecurity\s+definer\b", st, re.I)),
            "search_path": bool(re.search(r"\bset\s+search_path\b", st, re.I)),
            "trigger": bool(re.search(r"\breturns\s+trigger\b", st, re.I)),
        })
    return out


def _revoked_functions(stmts: list[tuple[str, str]]) -> tuple[set[str], list[int], list[int]]:
    """What revokes EXECUTE from public/anon, and where (positions are statement indexes, in file order):
    - names of functions revoked one by one,
    - positions of blanket revokes (`on all functions in schema`, or a DO loop that revokes), which cover only
      the functions created BEFORE them, because later functions get the default grants again,
    - positions of `alter default privileges ... revoke`, which cover only functions created AFTER them."""
    names: set[str] = set()
    blanket_after: list[int] = []   # covers earlier functions
    default_before: list[int] = []  # covers later functions
    for pos, (_, st) in enumerate(stmts):
        low = st.lower()
        if low.startswith("alter default privileges") and "revoke" in low and "execute" in low and "functions" in low:
            if re.search(r"\bfrom\s+.*\b(public|anon)\b", low):
                default_before.append(pos)
            continue
        if re.match(r"do\b", low) and "revoke" in low and re.search(r"\bfunction", low) and re.search(r"\b(public|anon)\b", low):
            blanket_after.append(pos)  # e.g. a hardening loop over every function
            continue
        m = REVOKE.match(st)
        if not m or not re.search(r"\b(execute|all)\b", m.group(1), re.I):
            continue
        if not _roles(m.group(3)) & {"public", "anon"}:
            continue
        target = m.group(2)
        if re.match(r"all\s+functions\s+in\s+schema", target, re.I):
            blanket_after.append(pos)
        elif re.match(r"(function|routine)\b", target, re.I):
            names |= {bare(n) for n in re.findall(rf"({NAME})\s*\(", target[target.index(" "):])}
    return names, blanket_after, default_before


def function_findings(stmts: list[tuple[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    revoked, blanket_after, default_before = _revoked_functions(stmts)
    for pos, (path, st) in enumerate(stmts):
        f = next(iter(_functions([(path, st)])), None)
        if f is None:
            continue
        if f["definer"] and not f["search_path"]:
            out.append(Finding("db_access", "high", f"SECURITY DEFINER function '{f['name']}' has no fixed search_path",
                               "It runs with its owner's rights, and without `SET search_path` a caller can plant a "
                               "look-alike table or function in a schema searched first.", f["path"],
                               fix=f"Add `SET search_path = ''` (and schema-qualify names inside), or "
                                   f"`SET search_path = public, pg_temp`, to function {f['name']}.",
                               tags=["owasp-a01"]))
        covered = (f["trigger"] or f["name"] in revoked
                   or any(b > pos for b in blanket_after) or any(d < pos for d in default_before))
        if covered:
            continue
        sev = "high" if f["definer"] else "low"
        out.append(Finding("db_access", sev, f"Function '{f['name']}' can be run by anyone",
                           "Postgres grants EXECUTE to PUBLIC unless it is revoked" +
                           (", and this function runs with its owner's rights." if f["definer"] else "."),
                           f["path"],
                           fix=f"REVOKE EXECUTE ON FUNCTION {f['name']}(...) FROM PUBLIC, anon; then GRANT EXECUTE "
                               "only to the roles that need it. " + ACCEPT,
                           tags=["owasp-a01"]))
    return out


# ---- views -----------------------------------------------------------------------------------------------------
def view_findings(stmts: list[tuple[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    for path, st in stmts:
        m = VIEW.match(st)
        if not m or re.match(r"create\s+materialized", st, re.I):
            continue
        if re.search(r"security_invoker\s*=\s*(true|on|1)", st, re.I):
            continue
        high = "supabase" in {p.lower() for p in Path(path).parts}
        out.append(Finding("db_access", "high" if high else "medium",
                           f"View '{bare(m.group(1))}' is not security_invoker",
                           "A view runs with its owner's rights, so it skips row-level security on the tables "
                           "underneath and can show every tenant's rows.", path,
                           fix="Create it WITH (security_invoker = true) (Postgres 15+), or put the tenant filter in "
                               "the view itself. " + ACCEPT, tags=["owasp-a01"]))
    return out


# ---- grants ----------------------------------------------------------------------------------------------------
def grant_gaps(grants: list[tuple[str, str, str, set]], pols: dict[str, list[dict]], enabled: set[str]) -> list[Finding]:
    """Grants to anon/authenticated that no policy covers. `grants` are (where, table, role, privileges). Works on
    data, so the static check (SQL files) and the live catalog audit share it. Tables without RLS are left to
    db_rules."""
    out: list[Finding] = []
    merged: dict[tuple[str, str, str], set] = {}  # one finding per table and role, not one per privilege row
    for where, t, role, privs in grants:
        merged.setdefault((where, t, role), set()).update(privs)
    for (where, t, role), privs in merged.items():
        if t not in enabled:
            continue
        uncovered = sorted(
            p for p in privs & ({"select"} | WRITES)
            if not any(role in pol["roles"] or "public" in pol["roles"]
                       for pol in pols.get(t, []) if pol["cmd"] in (p, "all")))
        if uncovered:
            out.append(Finding(
                "db_access", "medium" if role in ("anon", "public") else "low",
                f"Grant on '{t}' to {role} goes beyond its policies",
                f"{role} is granted {', '.join(uncovered).upper()} on '{t}' but no policy allows it. Safe "
                "while row-level security stays enabled, but the grant is wider than the rules.", where,
                fix="Remove the grants no policy needs (REVOKE ... FROM " + role + "). " + ACCEPT))
    return out


def grant_findings(stmts: list[tuple[str, str]], enabled: set[str]) -> list[Finding]:
    """Static version: read GRANT statements from SQL files."""
    pols: dict[str, list[dict]] = {}
    for _, st in stmts:
        p = db_rules.parse_policy(st)
        if p:
            pols.setdefault(bare(p["table"]), []).append(p)
    revoked_anon_tables = False  # a revoke from anon on tables anywhere in the migrations
    for _, st in stmts:
        m = REVOKE.match(st)
        if m and "anon" in _roles(m.group(3)) and not NON_TABLE.match(m.group(2).strip()):
            revoked_anon_tables = True
    out: list[Finding] = []
    grants: list[tuple[str, str, str, set]] = []
    for path, st in stmts:
        m = GRANT.match(st)
        if not m:
            continue
        target = m.group(2).strip()
        if NON_TABLE.match(target):
            continue
        roles = _roles(m.group(3)) & {"anon", "authenticated", "public"}
        if not roles:
            continue
        privs = _privs(m.group(1))
        if re.match(r"all\s+tables\s+in\s+schema", target, re.I):
            if "anon" in roles and not revoked_anon_tables:
                out.append(Finding("db_access", "medium", "Blanket grant on all tables to anon",
                                   "Every current table is granted to the anonymous role. Row-level security is the "
                                   "only thing left between the public and the data.", path,
                                   fix="Grant only the tables anonymous users need, or revoke from anon and rely on "
                                       "explicit grants. " + ACCEPT))
            continue
        for t in (bare(x) for x in split_top_level(re.sub(r"^table\s+", "", target, flags=re.I))):
            for role in sorted(roles):
                grants.append((path, t, role, privs))
    return out + grant_gaps(grants, pols, enabled)


# ---- storage ---------------------------------------------------------------------------------------------------
# `update storage.buckets set <col> = <value> [where id = 'name']`, also when it sits inside a quoted string in a DO
# block (EXECUTE '...'), where every quote is doubled.
BUCKET_UPDATE = re.compile(
    r"update\s+storage\.buckets\s+set\s+(file_size_limit|public)\s*=\s*([^\s,;']+)"
    r"(?:[^;]{0,200}?\bwhere\s+id\s*=\s*'{1,2}([^']+)'{1,2})?", re.I)


def later_bucket_settings(stmts: list[tuple[str, str]]) -> dict[str, set[str]]:
    """Bucket settings applied by an UPDATE anywhere in the migrations. A bucket created without a size limit (or
    public) in an early migration is often fixed in a later one, so the early insert alone proves nothing.
    Returns {"limited": ids with a size limit set, "private": ids made private}; "*" means every bucket (no WHERE).
    File order is not simulated: any such update counts."""
    out: dict[str, set[str]] = {"limited": set(), "private": set()}
    for _, st in stmts:
        for m in BUCKET_UPDATE.finditer(st):
            col, val, bid = m.group(1).lower(), m.group(2).lower(), (m.group(3) or "*")
            if col == "file_size_limit" and val != "null":
                out["limited"].add(bid)
            elif col == "public" and val == "false":
                out["private"].add(bid)
    return out


def storage_findings(stmts: list[tuple[str, str]], later: dict[str, set[str]] | None = None) -> list[Finding]:
    later = later or {"limited": set(), "private": set()}
    out: list[Finding] = []
    for path, st in stmts:
        p = db_rules.parse_policy(st)
        if p and p["table"].endswith("storage.objects") and "bucket_id" not in st.lower():
            out.append(Finding("db_access", "medium", f"Storage policy '{p['name']}' is not limited to one bucket",
                               "A policy on storage.objects without a bucket_id condition applies to every bucket, "
                               "including ones added later.", path,
                               fix="Add `bucket_id = '<name>'` to USING and WITH CHECK. " + ACCEPT,
                               tags=["owasp-a01"]))
        m = re.match(r"insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*\((.*?)\)\s*(?:on\s+conflict.*)?$",
                     st, re.I | re.S)
        if m:
            cols = [c.strip().lower() for c in m.group(1).split(",")]
            vals = split_top_level(m.group(2))
            bid = vals[0].strip("' ") if vals else "?"
            unlimited = len(vals) == len(cols) and ("file_size_limit" not in cols or vals[cols.index("file_size_limit")].lower() == "null")
            if unlimited and not ({bid, "*"} & later["limited"]):
                out.append(Finding("db_access", "low", f"Storage bucket '{bid}' has no file size limit",
                                   "Without a limit one user can upload very large files (cost and abuse).", path,
                                   fix="Set file_size_limit on the bucket (and allowed_mime_types). " + ACCEPT))
            if ("public" in cols and len(vals) == len(cols) and vals[cols.index("public")].lower() == "true"
                    and not ({bid, "*"} & later["private"])):
                out.append(Finding("db_access", "medium", f"Storage bucket '{bid}' is public",
                                   "Anyone with a file's URL can read it without signing in.", path,
                                   fix="Make the bucket private and serve files through short-lived signed URLs. "
                                       + ACCEPT, tags=["owasp-a01"]))
        if re.match(r"update\s+storage\.buckets\s+set\s+public\s*=\s*true", st, re.I):
            out.append(Finding("db_access", "medium", "Storage bucket made public",
                               "Anyone with a file's URL can read it without signing in.", path,
                               fix="Keep the bucket private and use signed URLs. " + ACCEPT, tags=["owasp-a01"]))
    return out


# ---- privileged keys in front-end files ------------------------------------------------------------------------
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
CLIENT_ENV = re.compile(r"\b((?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*"
                        r"(?:SERVICE_ROLE|SERVICE_KEY|SECRET|PRIVATE_KEY)[A-Z0-9_]*)")
KEY_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".json",
                ".env", ".local", ".production", ".development", ".example", ".toml", ".yml", ".yaml")


def _jwt_role(token_payload: str) -> str:
    try:
        raw = base64.urlsafe_b64decode(token_payload + "=" * (-len(token_payload) % 4))
        return str(json.loads(raw).get("role", ""))
    except (ValueError, TypeError, AttributeError):
        return ""


def key_findings(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in JWT.finditer(text):
        if _jwt_role(m.group(1)) == "service_role":
            out.append(Finding("db_access", "critical", "Service-role key found in a file",
                               "A Supabase service_role key bypasses all row-level security. Anyone who can read "
                               "this file can read and change every row.", path,
                               fix="Rotate the key now, remove it from the file and git history, and keep it only in "
                                   "server-side environment variables.", tags=["secrets", "owasp-a02"]))
            break
    seen: set[str] = set()
    for m in CLIENT_ENV.finditer(text):
        if m.group(1) in seen:
            continue
        seen.add(m.group(1))
        out.append(Finding("db_access", "high", f"Privileged key exposed to the browser: {m.group(1)}",
                           "Variables with this prefix are compiled into the page every visitor downloads.", path,
                           fix="Rename it without the public prefix and read it only on the server. Rotate it if "
                               "it was ever deployed.", tags=["secrets", "owasp-a02"]))
    return out


def run(cfg, http) -> list[Finding]:
    files = db_rules.sql_files(cfg.source_dir)
    findings: list[Finding] = []
    scanned_keys = 0
    for p in walk(cfg.source_dir, KEY_SUFFIXES):
        try:
            findings += key_findings(str(p), p.read_text(errors="replace"))
            scanned_keys += 1
        except OSError:
            continue
    if not files and not scanned_keys:
        raise Skipped("no .sql or front-end files found under source_dir", applicable=False)
    stmts = [(str(p), st) for p, sql in files for st in split_statements(sql)]
    enabled: set[str] = set()
    for _, sql in files:
        enabled |= db_rules.protected_tables(sql)
    sql_findings = (function_findings(stmts) + view_findings(stmts) + grant_findings(stmts, enabled)
                    + storage_findings(stmts, later_bucket_settings(stmts)))
    findings += [f for f in sql_findings if is_changed(f.target)]  # --diff-since: whole-project context, changed-file report
    return findings
