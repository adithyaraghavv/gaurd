"""Static database access-rule check for SQL migration files (Postgres/Supabase).

Flags tables created without row-level security and policies that allow
everything. If your database is only reachable through a trusted backend, the
medium findings may be acceptable; for Supabase (client talks to the database)
they are high."""
from __future__ import annotations

import re

from ..files import walk
from ..findings import Finding

CREATE = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?', re.I)
RLS = re.compile(r'alter\s+table\s+(?:only\s+)?(?:"?public"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security', re.I)
OPEN_POLICY = re.compile(r'create\s+policy\s+"?([^"\n]+?)"?\s+on\s+(?:"?public"?\.)?"?(\w+)"?[^;]*?using\s*\(\s*true\s*\)', re.I | re.S)
SKIP_SCHEMAS = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?"?(?:auth|storage|extensions|pg_catalog)"?\.', re.I)


def evaluate_sql(path: str, sql: str, high: bool) -> list[Finding]:
    out: list[Finding] = []
    sql_no_comments = re.sub(r"--[^\n]*", "", sql)
    created = {m.group(1) for m in CREATE.finditer(sql_no_comments)
               if not SKIP_SCHEMAS.match(sql_no_comments[m.start():])}
    protected = {m.group(1) for m in RLS.finditer(sql_no_comments)}
    for table in sorted(created - protected):
        out.append(Finding("db_rules", "high" if high else "medium",
                           f"Table '{table}' has no row-level security",
                           "Anyone who can reach the database API may read or write all rows.", path,
                           fix=f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; then add per-user/tenant policies. "
                               "Ignore only if this table is never reachable by clients.",
                           tags=["owasp-a01"]))
    for m in OPEN_POLICY.finditer(sql_no_comments):
        out.append(Finding("db_rules", "high", f"Policy '{m.group(1)}' on '{m.group(2)}' allows all rows",
                           "USING (true) makes the policy match every row.", path,
                           fix="Restrict the policy to the owner/tenant, e.g. USING (tenant_id = auth.uid()).",
                           tags=["owasp-a01"]))
    return out


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    for p in walk(cfg.source_dir, (".sql",)):
        high = "supabase" in {part.lower() for part in p.parts}
        try:
            findings += evaluate_sql(str(p), p.read_text(errors="replace"), high)
        except OSError:
            continue
    return findings
