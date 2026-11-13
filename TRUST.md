# Trust model

**What you can verify:** the whole kit is readable Python with no runtime dependencies. Read it once, then pin it by commit hash.

**What it still relies on:** semgrep, gitleaks and trivy are third-party tools. Pin exact versions, verify checksums, and prefer their official GitHub Actions pinned to a commit SHA. They are optional; every other check works without them.

**The auto-fix loop:** it only works if the coding agent is honest. `fix_tasks.md` tells the agent to fix root causes and not to weaken the scanner, but a determined agent could still hide a finding. Review diffs, especially changes under `.claude/`, config files, and anything that touches guard.

**What it does not do:**
- It is not a full pentest. It finds common, high-value problems, not complex business-logic flaws.
- A clean report does not mean secure. Add code review, parameterized queries, row-level security, and dependency updates.
- No exploitation: probes send quotes, forged copies of your own test token, and harmless test files, and check responses.
- The `ai` check is partly heuristic (regex over source); expect some false positives and misses.
- `db_rules` only reads `.sql` files; it cannot see policies created through a dashboard.

**Safety limits:** live checks refuse unlisted or production-looking hosts. The mass-assignment and upload checks write data, so use staging with dummy data only.

**Added in round 2, and what to know about each:**
- `supabase_audit` never writes. Its live part sends a fixed list of SELECT statements inside a `BEGIN READ ONLY` transaction through `psql`, refuses any statement that is not a single SELECT, and only talks to hosts you list that do not look like production. Use a read-only database role anyway. Leaked-password protection and other hosted-only settings cannot be read from your code: they only appear if you provide an advisors export.
- `tenant_routes` write checks can change or delete tenant A's data if your isolation is broken. They are off unless you turn them on. A 400/422 means the route validated the body first, so it proves nothing until you supply a valid body.
- `prod_config` is a lint over files. Its rate-limit and security-header findings are heuristics and can be wrong when a proxy or provider does that work. It never connects anywhere and never prints a secret's value.
- The scanner installer only installs what you pinned and checksummed. Guard cannot tell whether the checksum you wrote is the right one; that is your check.
- Launch-readiness sign-offs are your statements. Guard shows them but cannot verify them.
