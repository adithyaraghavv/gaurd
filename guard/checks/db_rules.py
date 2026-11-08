"""Static database access-rule check for SQL migration files (Postgres/Supabase).

Flags tables created without row-level security and policies that allow
everything. If your database is only reachable through a trusted backend, the
medium findings may be acceptable; for Supabase (client talks to the database)
they are high."""
from __future__ import annotations

import re
from pathlib import Path

from ..files import walk
from ..findings import Finding

CREATE = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?', re.I)
RLS = re.compile(r'alter\s+table\s+(?:only\s+)?(?:"?public"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security', re.I)
OPEN_POLICY = re.compile(r'create\s+policy\s+"?([^"\n]+?)"?\s+on\s+(?:"?public"?\.)?"?(\w+)"?[^;]*?using\s*\(\s*true\s*\)', re.I | re.S)
# RLS enabled through a loop, e.g. DO $$ ... FOREACH t IN ARRAY ARRAY['a','b'] ... format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t)
DYNAMIC_RLS = re.compile(r"enable\s+row\s+level\s+security", re.I)
LITERAL = re.compile(r"'([A-Za-z_][A-Za-z0-9_]*)'")
SKIP_SCHEMAS = re.compile(r'create\s+table\s+(?:if\s+not\s+exists\s+)?"?(?:auth|storage|extensions|pg_catalog)"?\.', re.I)


def _strip(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


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


def open_policies(path: str, sql: str) -> list[Finding]:
    out: list[Finding] = []
    for m in OPEN_POLICY.finditer(_strip(sql)):
        out.append(Finding("db_rules", "high", f"Policy '{m.group(1)}' on '{m.group(2)}' allows all rows",
                           "USING (true) makes the policy match every row.", path,
                           fix="Restrict the policy to the owner/tenant, e.g. USING (tenant_id = auth.uid()).",
                           tags=["owasp-a01"]))
    return out


def missing_rls(path: str, tables: set[str], high: bool) -> list[Finding]:
    return [Finding("db_rules", "high" if high else "medium",
                    f"Table '{t}' has no row-level security",
                    "Anyone who can reach the database API may read or write all rows.", path,
                    fix=f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY; then add per-user/tenant policies. "
                        "Ignore only if this table is never reachable by clients.",
                    tags=["owasp-a01"]) for t in sorted(tables)]


def evaluate_sql(path: str, sql: str, high: bool) -> list[Finding]:
    """Single-file check (kept for direct use and tests)."""
    return missing_rls(path, created_tables(sql) - protected_tables(sql), high) + open_policies(path, sql)


def run(cfg, http) -> list[Finding]:
    """Looks at all migration files together: RLS enabled in a later file (or by a
    loop) counts for a table created in an earlier file."""
    files: list[tuple[Path, str]] = []
    for p in sorted(walk(cfg.source_dir, (".sql",))):
        try:
            files.append((p, p.read_text(errors="replace")))
        except OSError:
            continue
    protected: set[str] = set()
    for _, sql in files:
        protected |= protected_tables(sql)
    findings: list[Finding] = []
    for p, sql in files:
        high = "supabase" in {part.lower() for part in p.parts}
        findings += missing_rls(str(p), created_tables(sql) - protected, high)
        findings += open_policies(str(p), sql)
    return findings
