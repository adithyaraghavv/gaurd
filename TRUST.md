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
