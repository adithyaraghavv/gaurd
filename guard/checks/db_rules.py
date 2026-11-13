"""Static database access-rule check for SQL migration files (Postgres/Supabase).

Flags tables created without row-level security and policies that match every row. A policy is judged by what
it allows and to whom: an anonymous read-only policy on a public catalog is a normal pattern (low), while a
policy that lets anyone write, or that lets every signed-in user read every row, is not (high).

If your database is only reachable through a trusted backend, the medium findings may be acceptable; for
Supabase (client talks to the database) they are high. Findings you have reviewed can be recorded under
`accepted_risks` in the config instead of being ignored."""
from __future__ import annotations

import re
from pathlib import Path

from ..coverage import Skipped
from ..files import is_changed, walk
from ..findings import Finding
from ..sqlscan import bare, ident, split_statements, strip_comments

CREATE = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?', re.I)
RLS = re.compile(r'alter\s+table\s+(?:only\s+)?(?:"?public"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security', re.I)
# RLS enabled through a loop, e.g. DO $$ ... FOREACH t IN ARRAY ARRAY['a','b'] ... format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t)
DYNAMIC_RLS = re.compile(r"enable\s+row\s+level\s+security", re.I)
LITERAL = re.compile(r"'([A-Za-z_][A-Za-z0-9_]*)'")
SKIP_SCHEMAS = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?"?(?:auth|storage|extensions|pg_catalog)"?\.', re.I)

POLICY = re.compile(r'create\s+policy\s+("[^"]+"|\S+)\s+on\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?)', re.I)
CMD = re.compile(r"\bfor\s+(all|select|insert|update|delete)\b", re.I)
ROLES = re.compile(r"\bto\s+(.+?)(?=\s+(?:using|with\s+check)\b|$)", re.I | re.S)
USING_TRUE = re.compile(r"\busing\s*\(\s*true\s*\)", re.I)
CHECK_TRUE = re.compile(r"\bwith\s+check\s*\(\s*true\s*\)", re.I)

ACCEPT_HINT = ("If this table is meant to be public (a catalog, reference data), record it under accepted_risks in "
               "guard.config.json with a reason and an owner; do not weaken the policy to make this go away.")


def _strip(sql: str) -> str:
    return strip_comments(sql)


def created_tables(sql: str) -> set[str]:
    s = _strip(sql)
    return {m.group(1) for m in CREATE.finditer(s) if not SKIP_SCHEMAS.match(s[m.start():])}


def protected_tables(sql: str) -> set[str]:
    """Tables with RLS enabled, including ones enabled by a loop over a list of names."""
    s = _strip(sql)
    prot = {m.group(1) for m in RLS.finditer(s)}
    for blk in re.finditer(r"\$(\w*)\$(.*?)\$\1\$", s, re.S):  # DO $$ ... $$ blocks
        body = blk.group(2)
        if DYNAMIC_RLS.search(body) and ("%I" in body or "format" in body.lower() or "execute" in body.lower()):
            prot |= set(LITERAL.findall(body))
    return prot


def parse_policy(stmt: str) -> dict | None:
    """The parts of one CREATE POLICY statement that decide how risky it is."""
    m = POLICY.match(stmt.strip())
    if not m:
        return None
    cmd = CMD.search(stmt)
    roles = ROLES.search(stmt)
    names = {ident(r) for r in re.split(r"\s*,\s*", roles.group(1).strip())} if roles else {"public"}
    return {
        "name": m.group(1).strip('"'),
        "table": ident(m.group(2)),
        "cmd": cmd.group(1).lower() if cmd else "all",
        "roles": names,
        "using_true": bool(USING_TRUE.search(stmt)),
        "check_true": bool(CHECK_TRUE.search(stmt)),
        "text": stmt,
    }


def policies(sql: str) -> list[dict]:
    return [p for p in (parse_policy(s) for s in split_statements(sql)) if p]


def _policy_finding(path: str, pol: dict) -> Finding | None:
    cmd, roles = pol["cmd"], pol["roles"]
    # What the "true" expression opens up: reads (USING on select/update/delete/all) or writes (CHECK on
    # insert/update/all, and USING on update/delete).
    opens_read = pol["using_true"] and cmd in ("select", "all")
    opens_write = (pol["using_true"] and cmd in ("update", "delete", "all")) or \
                  (pol["check_true"] and cmd in ("insert", "update", "all"))
    if not (opens_read or opens_write):
        return None
    table, name = pol["table"], pol["name"]
    where = f"'{bare(table)}'"
    if roles <= {"service_role"}:
        return Finding("db_rules", "info", f"Policy '{name}' on {where} is open, but only to service_role",
                       "service_role bypasses row-level security anyway, so this policy changes nothing.", path)
    if opens_write:
        return Finding("db_rules", "high", f"Policy '{name}' on {where} allows all rows",
                       f"A {cmd.upper()} policy with `true` lets {_who(roles)} change any row.", path,
                       fix="Restrict the policy to the owner or tenant, using your own ownership column, e.g. "
                           "USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid()). " + ACCEPT_HINT,
                       tags=["owasp-a01"])
    if roles <= {"anon"}:
        return Finding("db_rules", "low", f"Public read policy '{name}' on {where} (anonymous, all rows)",
                       "Anonymous users can read every row. That is normal for a public catalog and wrong for "
                       "anything personal.", path,
                       fix="Confirm the table holds only data you publish on purpose. " + ACCEPT_HINT,
                       tags=["owasp-a01"])
    return Finding("db_rules", "high", f"Policy '{name}' on {where} allows all rows",
                   f"`USING (true)` lets {_who(roles)} read every row, including other users' rows.", path,
                   fix="Restrict the policy to the owner or tenant, using your own ownership column, e.g. "
                       "USING (owner_id = auth.uid()). " + ACCEPT_HINT,
                   tags=["owasp-a01"])


def _who(roles: set[str]) -> str:
    if "public" in roles:
        return "anyone, signed in or not,"
    if "anon" in roles:
        return "anonymous users and other roles"
    return "every signed-in user"


def open_policies(path: str, sql: str) -> list[Finding]:
    return [f for f in (_policy_finding(path, p) for p in policies(sql)) if f]


def missing_rls(path: str, tables: set[str], high: bool) -> list[Finding]:
    return [Finding("db_rules", "high" if high else "medium",
                    f"Table '{t}' has no row-level security",
                    "Anyone who can reach the database API may read or write all rows.", path,
                    fix=f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY; then add per-user/tenant policies. "
                        "If the table is never reachable by clients, or is deliberately public, record it under "
                        "accepted_risks in guard.config.json with a reason and an owner.",
                    tags=["owasp-a01"]) for t in sorted(tables)]


def evaluate_sql(path: str, sql: str, high: bool) -> list[Finding]:
    """Single-file check (kept for direct use and tests)."""
    return missing_rls(path, created_tables(sql) - protected_tables(sql), high) + open_policies(path, sql)


def sql_files(source_dir: str) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for p in sorted(walk(source_dir, (".sql",), all_files=True)):  # context: every file, even in diff mode
        try:
            files.append((p, p.read_text(errors="replace")))
        except OSError:
            continue
    return files


def run(cfg, http) -> list[Finding]:
    """Looks at all migration files together: RLS enabled in a later file (or by a
    loop) counts for a table created in an earlier file."""
    files = sql_files(cfg.source_dir)
    if not files:
        raise Skipped("no .sql files found under source_dir", applicable=False)
    protected: set[str] = set()
    for _, sql in files:
        protected |= protected_tables(sql)
    findings: list[Finding] = []
    for p, sql in files:
        if not is_changed(p):  # --diff-since: judged with the whole project, but only changed files are reported
            continue
        high = "supabase" in {part.lower() for part in p.parts}
        findings += missing_rls(str(p), created_tables(sql) - protected, high)
        findings += open_policies(str(p), sql)
    return findings
