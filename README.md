# guard

A small security testing kit you own and can read end to end. Reuse it for every app or startup you build, whatever the stack or domain.

- **Zero third-party Python dependencies** (stdlib only), so there is no package here that could be poisoned.
- **Scope guard**: live checks refuse any host not in `allowed_hosts`, and refuse production-looking hosts unless you opt in.
- **Static stage** wraps semgrep, gitleaks and trivy if installed (pin their versions).
- **Auto-fix loop** for Claude Code: scan, fix, re-scan until clean, then a plain-English summary.
- **Reports**: Markdown, JSON, SARIF (GitHub code scanning), plus `fix_tasks.md` and `summary.md`.

## Checks

| Check | What it looks for | Needs network |
|---|---|---|
| headers | missing security headers, version leaks | yes |
| cors | origin reflection, wildcard with credentials | yes |
| cookies | missing HttpOnly / Secure / SameSite | yes |
| exposed | `.env`, `.git`, DB dumps, admin/debug pages | yes |
| tenant | user B reading user A's data (IDOR), open routes | yes |
| jwt | never-expiring tokens; server accepting forged tokens | partly |
| injection | SQL injection error and boolean probes | yes |
| mass_assignment | client able to set role, tenant, owner fields | yes |
| upload | dangerous file types accepted | yes |
| ratelimit | no throttling on login | yes |
| db_rules | SQL tables without row-level security, `USING (true)` | no |
| ai | exposed LLM keys, model output to eval/HTML, prompt-injection leaks | partly |

## Add it to any new project

```bash
pip install /path/to/guard        # or: pip install git+https://github.com/<you>/guard
cd your-new-app
guard init                            # writes guard.config.json (gitignore it)
cp /path/to/guard/templates/CLAUDE.md .
cp -r /path/to/guard/templates/.claude .
cp /path/to/guard/.github/workflows/guard.yml .github/workflows/
```

Add `guard_out/` and `guard.config.json` to the app's `.gitignore`. Edit `guard.config.json` with your staging URL, allowed host, probe paths and the optional sections (uploads, AI endpoint, mass-assignment targets).

## The fix loop in Claude Code

Two ways, and you can use both:

1. **Automatic (Stop hook).** `.claude/settings.json` runs `guard gate` whenever Claude tries to finish. The gate runs the offline checks. If there are blocking issues it sends Claude back with `fix_tasks.md`, and it re-runs after every fix. When clean, it makes Claude give you the summary. It gives up after `max_fix_rounds` (default 5) and makes Claude explain what is left. It stays silent when nothing changed. Set `GUARD_GATE=off` to disable it. If you already have a `.claude/settings.json`, merge the hook in.
2. **On demand.** Type `/guard` in Claude Code to run the full loop, including live staging checks if you confirm they are safe.

Live checks send real requests, so the automatic gate never runs them; use `/guard` or `guard scan` for those.

## Scheduled scans

The workflow runs a live scan of staging every Monday and opens a GitHub issue with the summary if something is found. Store your config in a `GUARD_CONFIG_JSON` secret and tokens in `TENANT_A_TOKEN` / `TENANT_B_TOKEN`.

## Rules

1. Test only systems you own, on staging with dummy data.
2. Never commit `guard.config.json` or tokens.
3. Live checks are low-impact but real: the rate-limit test sends up to 100 requests, and mass-assignment and upload tests write to the endpoints you list.

See TRUST.md for what this kit does and does not protect against.
