from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, accept, dryrun, explain, files as filesmod, gitdiff, readiness, report, scanners
from .checks import ALL_CHECKS, OFFLINE_OK, PROBE_PATH_CHECKS
from .claude_setup import install
from .config import DEFAULT_CONFIG, PLACEHOLDER_SUFFIXES, Config
from .coverage import NA, OFF, RAN, SKIPPED, TOOLS, Coverage, Skipped, required_missing, result_line
from .loop import decide, previous_skipped, record_run, write_fix_tasks, write_summary
from .runners import INSTALL_HINT, scan_tools
from .scope import PROD_HINTS, Scope, ScopeError, ScopedHTTP

# Exit codes of `guard scan`
EXIT_OK, EXIT_BLOCKING, EXIT_CONFIG, EXIT_REFUSED, EXIT_PARTIAL = 0, 1, 2, 3, 4
# Checks that need no network. Together with the outside scanners they are the "scanner checks" in the result line.
SCANNER_NAMES = set(TOOLS) | OFFLINE_OK | {"static"}


def _run_stages(cfg: Config, stages: set[str], http):
    """Run the selected checks. Returns (findings, notes, coverage): coverage says, for every check, whether it
    ran, was skipped (and why) or was switched off, so a skipped check can never pass as a clean one."""
    findings: list = []
    coverage: list[Coverage] = []
    if "static" in stages:
        f, cov = scan_tools(cfg.source_dir)
        findings += f
        coverage += cov
    else:
        coverage.append(Coverage("static scanners (semgrep, gitleaks, trivy)", OFF, "not selected (--only)"))
    for name, fn in ALL_CHECKS.items():
        if name not in stages:
            coverage.append(Coverage(name, OFF, "not selected (--only)"))
            continue
        if http is None and name not in OFFLINE_OK:
            coverage.append(Coverage(name, OFF, "live check; live checks are off (--no-live, or the automatic gate)"))
            continue
        if hasattr(http, "current"):
            http.current = name  # a dry run records which check would send each request
        try:
            found = fn(cfg, http)  # ScopeError propagates to the caller
        except Skipped as e:
            coverage.append(Coverage(name, SKIPPED if e.applicable else NA, e.reason))
            continue
        except ScopeError:
            raise  # a refused host stops the scan on purpose
        except Exception as e:  # a bug in one check must not take the scan down, nor pass as a clean result
            print(f"guard: check '{name}' crashed ({type(e).__name__}: {e}); it is marked SKIPPED", file=sys.stderr)
            coverage.append(Coverage(name, SKIPPED, f"crashed: {type(e).__name__}"))
            continue
        findings += found
        detail = "; ".join(f.title for f in found if "coverage-note" in f.tags)
        if name in PROBE_PATH_CHECKS and len(cfg.probe_paths) > cfg.max_probe_paths and http is not None:
            cut = f"checked the first {cfg.max_probe_paths} of {len(cfg.probe_paths)} probe_paths " \
                  f"(raise max_probe_paths to check the rest)"
            detail = f"{detail}; {cut}" if detail else cut
        if http is None and name in {"jwt", "ai"}:
            detail = (detail + "; " if detail else "") + "code part only (live probes are off)"
        coverage.append(Coverage(name, RAN, detail))
    active, accepted, notes = accept.apply(findings, cfg.accepted_risks)
    return active, notes, coverage, accepted


def _finish(cfg: Config, findings, notes, out_dir: str, coverage=None, accepted=None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    prev = previous_skipped(out_dir)  # read BEFORE this run overwrites it
    ready = readiness.items(cfg.launch_signoffs)
    (out / "report.md").write_text(report.to_markdown(findings, notes, coverage, accepted, prev, ready))
    (out / "report.json").write_text(report.to_json(findings, notes, coverage, accepted, ready))
    (out / "report.sarif").write_text(report.to_sarif(findings))
    result = record_run(out_dir, findings, cfg.fail_on, coverage, accepted, notes)
    result["readiness"] = ready
    write_fix_tasks(out_dir, result)
    write_summary(out_dir, result, cfg.fail_on)  # always: a stale summary from an earlier session must not linger
    return result


def _has_changes() -> bool:
    try:
        p = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return True
    if p.returncode != 0:
        return True
    lines = [l for l in p.stdout.splitlines() if "guard_out" not in l and "guard.config.json" not in l]
    return bool(lines)


def cmd_gate(args) -> int:
    """Claude Code Stop hook. Exit 2 sends Claude back to fix issues; exit 0 lets it stop."""
    if os.environ.get("GUARD_GATE") == "off":
        return 0
    try:
        sys.stdin.read() if not sys.stdin.isatty() else None  # hook payload; not needed
    except OSError:
        pass
    out = Path(args.out)
    if not Path(args.config).exists():
        return 0  # project has not opted in to guard (no config): stay silent
    state_path = out / "gate_state.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    if not state and not _has_changes():
        return 0
    try:
        cfg = Config.load(args.config)
    except (OSError, ValueError) as e:
        print(f"guard gate: config error: {e}", file=sys.stderr)
        return 0
    stages = set(ALL_CHECKS) | {"static"}
    findings, notes, coverage, accepted = _run_stages(cfg, stages, None)  # offline only: static + code checks
    result = _finish(cfg, findings, notes, args.out, coverage, accepted)
    code, kind, new_state = decide(len(result["blocking"]), state, cfg.max_fix_rounds,
                                   had_issues=result["had_blocking"])
    out.mkdir(parents=True, exist_ok=True)
    if new_state:
        state_path.write_text(json.dumps(new_state))
    elif state_path.exists():
        state_path.unlink()
    listing = "\n".join(f"- [{f.severity.upper()}] {f.title} ({f.target})" for f in result["blocking"][:15])
    if kind == "fix":
        print(f"guard gate: {len(result['blocking'])} blocking issue(s) found "
              f"(fix round {new_state['attempts']} of {cfg.max_fix_rounds}).\n"
              f"Read {args.out}/fix_tasks.md and fix each issue at its root cause. Do not weaken or edit "
              f"guard to hide findings. Do not stop until they are fixed; this check re-runs "
              f"automatically when you finish.\n\nBlocking now:\n{listing}", file=sys.stderr)
    elif kind == "summary":
        print(f"guard gate: all blocking issues are fixed after {result['rounds']} round(s). Before "
              f"stopping, read {args.out}/summary.md and tell the user in plain English: what was found, "
              f"what you changed for each issue, how many rounds it took, anything left for them to decide, "
              f"and what could not be verified. Then stop.", file=sys.stderr)
    elif kind == "gave_up":
        print(f"guard gate: reached the limit of {cfg.max_fix_rounds} fix rounds with "
              f"{len(result['blocking'])} issue(s) still open. Stop trying to fix them. Explain to the user "
              f"in plain English which issues remain, why they are hard to resolve, and what you recommend. "
              f"Details: {args.out}/summary.md\n{listing}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guard", description="Self-owned security testing kit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run static scanners and checks")
    s.add_argument("-c", "--config", default="guard.config.json")
    s.add_argument("--only", nargs="*", choices=[*ALL_CHECKS, "static"], help="limit to these stages")
    s.add_argument("-o", "--out", default="guard_out")
    s.add_argument("--no-live", action="store_true", help="skip network checks")
    s.add_argument("--allow-partial", action="store_true",
                   help="exit 0 even when required scanners (semgrep, gitleaks, trivy) did not run. The report still "
                        "says PARTIAL")
    s.add_argument("--dry-run", action="store_true",
                   help="list the requests a live scan would send, and send none of them")
    s.add_argument("--diff-since", metavar="COMMIT",
                   help="only scan files changed since COMMIT (or 'auto': the fork point from the default branch)")

    g = sub.add_parser("gate", help="Claude Code Stop hook: block stopping until issues are fixed")
    g.add_argument("-c", "--config", default="guard.config.json")
    g.add_argument("-o", "--out", default="guard_out")

    ini = sub.add_parser("init", help="write a starter guard.config.json and a test-user setup guide")
    ini.add_argument("--base-url", metavar="URL", help="your STAGING url (asked for when run in a terminal)")

    sub.add_parser("diff-base", help="print the commit to diff against, even when the repo has no `main`")

    d = sub.add_parser("doctor", help="show what is installed, configured and missing")
    d.add_argument("-c", "--config", default="guard.config.json")
    d.add_argument("--explain", metavar="CHECK", help="say what a check does and what it needs")
    d.add_argument("--install", nargs="*", metavar="TOOL",
                   help="install scanners from versions YOU pinned in scanners.lock (all of them if none are named)")
    d.add_argument("--lock", default="scanners.lock", help="the lock file for --install (default: scanners.lock)")

    st = sub.add_parser("setup", help="install the /guard command for Claude Code")
    st.add_argument("--hook", action="store_true",
                    help="also add the automatic Stop hook (runs in projects that have guard.config.json)")
    st.add_argument("--no-rules", action="store_true", help="do not add the guard rules to CLAUDE.md")
    st.add_argument("--project", action="store_true",
                    help="install into the current project (./.claude) instead of your user account")
    st.add_argument("--repo", metavar="OWNER/NAME",
                    help="GitHub repo that holds guard; lets /guard install guard itself in cloud sessions")
    st.add_argument("--home", help=argparse.SUPPRESS)

    args = p.parse_args(argv)

    if args.cmd == "setup":
        gitignore = None
        if args.project:
            claude_dir, rules_path = Path.cwd() / ".claude", Path.cwd() / "CLAUDE.md"
            gitignore = Path.cwd() / ".gitignore"
        else:
            claude_dir = (Path(args.home) if args.home else Path.home()) / ".claude"
            rules_path = claude_dir / "CLAUDE.md"
        try:
            lines = install(claude_dir, rules_path, hook=args.hook, rules=not args.no_rules,
                            repo=args.repo, gitignore=gitignore)
        except ValueError as e:
            print(f"setup error: {e}", file=sys.stderr)
            return 2
        for line in lines:
            print(line)
        if args.project:
            print("\nDone. Commit and push .claude/ and CLAUDE.md, then start a NEW Claude Code session "
                  "on that branch and type /guard")
        else:
            print("\nDone. Start a NEW Claude Code session in any project and type /guard")
        return 0

    if args.cmd == "init":
        return cmd_init(args)

    if args.cmd == "diff-base":
        try:
            ref, why = gitdiff.base_ref()
        except gitdiff.GitError as e:
            print(f"diff-base: {e}", file=sys.stderr)
            return EXIT_CONFIG
        print(ref)
        print(f"({why})", file=sys.stderr)
        return 0

    if args.cmd == "gate":
        return cmd_gate(args)

    if args.cmd == "doctor":
        return cmd_doctor(args)

    try:
        cfg = Config.load(args.config)
    except (OSError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    return cmd_scan(args, cfg)


def _wants_live(cfg: Config, stages: set[str], no_live: bool) -> bool:
    """True when this scan would talk to a running app or a database."""
    if no_live:
        return False
    if any(st not in OFFLINE_OK | {"static"} for st in stages):
        return True
    return bool(cfg.db_audit_url) and "supabase_audit" in stages  # the DB audit is a live check too


def cmd_scan(args, cfg: Config) -> int:
    stages = set(args.only) if args.only else {"static", *ALL_CHECKS}
    if args.dry_run:
        return cmd_dry_run(args, cfg, stages)
    if args.diff_since:
        try:
            filesmod.CHANGED = gitdiff.changed_files(args.diff_since)
        except gitdiff.GitError as e:
            print(f"--diff-since: {e}", file=sys.stderr)
            return EXIT_CONFIG
        print(f"--diff-since {args.diff_since}: scanning {len(filesmod.CHANGED)} changed file(s) "
              "(SQL and config checks still read the whole project for context)")
    if _wants_live(cfg, stages, args.no_live) and (why := cfg.live_blocker()):
        # Nothing has been sent. The starter config names a host you do not control, so a live scan is refused
        # until you have reviewed it.
        print(f"LIVE SCAN REFUSED: {why}\nCode-only checks still work: guard scan --no-live", file=sys.stderr)
        return EXIT_REFUSED
    http = None if args.no_live else ScopedHTTP(Scope(cfg.allowed_hosts, cfg.allow_production))
    try:
        findings, notes, coverage, accepted = _run_stages(cfg, stages, http)
    except ScopeError as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return EXIT_REFUSED

    result = _finish(cfg, findings, notes, args.out, coverage, accepted)
    # The first thing a person reads must not look like a pass when most of the work did not run.
    print(result_line(coverage, SCANNER_NAMES, len(findings), len(result["blocking"]), len(accepted)))
    print(f"Reports in {args.out}/ (summary: {args.out}/summary.md; fix list: {args.out}/fix_tasks.md)")
    if result["prev_skipped"]:
        still = [n for n in result["prev_skipped"] if any(c.name == n and c.status == SKIPPED for c in coverage)]
        if still:
            print(f"Still skipped from last time: {', '.join(still)}")
    ready = readiness.items(cfg.launch_signoffs)
    if not readiness.is_ready(ready):
        print(f"Launch readiness: {readiness.status_line(ready)} (see {args.out}/summary.md)")
    if result["blocking"]:
        return EXIT_BLOCKING
    missing = required_missing(coverage)
    if missing and not args.allow_partial:
        print("EXIT 4 (partial): required scanners did not run: " + ", ".join(c.name for c in missing) +
              ". Install them (`guard doctor`, `guard doctor --install`), or pass --allow-partial to accept a "
              "partial scan on purpose.", file=sys.stderr)
        return EXIT_PARTIAL
    return EXIT_OK


def cmd_dry_run(args, cfg: Config, stages: set[str]) -> int:
    """List every request a live scan would send, and send none of them."""
    why = cfg.live_blocker()
    if why:
        print(f"Note: a real live scan would be REFUSED right now: {why}\n")
    live = {n for n in ALL_CHECKS if n not in OFFLINE_OK and n in stages}
    http = dryrun.DryRunHTTP(Scope(cfg.allowed_hosts, cfg.allow_production))
    try:
        _run_stages(cfg, live, http)
    except ScopeError as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return EXIT_REFUSED
    if cfg.db_audit_url and "supabase_audit" in stages:
        from .checks import supabase_audit
        host = ""
        try:
            host = supabase_audit.check_target(cfg)
            refused = ""
        except ScopeError as e:
            refused = str(e)
        http.plan.append(dryrun.Planned("supabase_audit", "SELECT", f"postgresql://{host or '?'}/ "
                                        f"({len(supabase_audit.QUERIES)} read-only catalog queries, READ ONLY transaction)",
                                        "database role", "", refused))
    print(dryrun.format_plan(http.plan))
    return EXIT_OK


GUIDE = """# Setting up guard's live checks

Live checks send real requests to a running copy of your app. Do this only against a STAGING copy with dummy
data. Never production. Nothing in this file contains a secret; keep tokens in environment variables.

## 1. A staging copy
Deploy (or run) a separate copy of the app with fake data. Its address is the `base_url` in guard.config.json.

## 2. Two test tenants (for the cross-tenant test)
A "tenant" is whoever owns data: a workspace, studio, shop or team. Create TWO, each with:
- one test user,
- at least one record that really contains data (a client, an order, a file...).
Tenant B must never be able to see tenant A's records. Guard checks exactly that.

## 3. Get a login token for each test user
Sign in as each test user (through your app or its auth provider) and copy the access token (a long string
starting `eyJ...` for JWT-based auth). Put them in environment variables, never in the file:

    export TENANT_A_TOKEN="..."
    export TENANT_B_TOKEN="..."

(If your app has roles instead of tenants, make one test user per role and use `tokens` + `access_checks`:
see `guard doctor --explain access`.)

## 4. Tell guard what tenant A owns
In guard.config.json list a few URLs of tenant A's data (`tenant_a_resources`), for example `/api/clients/<id>`.
Use `guard doctor --explain tenant` and `guard doctor --explain tenant_routes` for the details.

## 5. Check, preview, then run
    guard doctor                 # what is installed, configured and missing
    guard scan --dry-run         # lists every request a live scan would send; sends none
    # when it all looks right, set "setup_complete": true in guard.config.json, then:
    guard scan

Checks that write data (mass_assignment, upload, ratelimit, tenant_routes writes) say so in
`guard doctor --explain <check>`. Use disposable data.
"""


def _ask_base_url() -> str:
    try:
        return input("Your STAGING url (for example https://staging.myapp.com), or press Enter to fill it in later: ").strip()
    except EOFError:
        return ""


def cmd_init(args) -> int:
    from urllib.parse import urlparse
    dest = Path("guard.config.json")
    if dest.exists():
        print("guard.config.json already exists", file=sys.stderr)
        return EXIT_CONFIG
    url = (args.base_url or "").strip()
    if not url and sys.stdin.isatty():
        url = _ask_base_url()
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if url:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not host:
            print(f"'{url}' is not a web address (start with https://).", file=sys.stderr)
            return EXIT_CONFIG
        if host.endswith(PLACEHOLDER_SUFFIXES):
            print(f"'{host}' is a placeholder. Use your real staging host.", file=sys.stderr)
            return EXIT_CONFIG
        if any(host.startswith(h) or h in host.split(".")[0] for h in PROD_HINTS) and host not in ("localhost", "127.0.0.1"):
            print(f"'{host}' looks like production. guard only tests staging: use a staging copy with dummy data.",
                  file=sys.stderr)
            return EXIT_CONFIG
        cfg.update({"base_url": f"{u.scheme}://{u.netloc}", "allowed_hosts": [host], "tenant_a_resources": [],
                    "probe_paths": ["/"], "injection_params": [], "rate_limit_path": "", "mass_assignment_targets": []})
    dest.write_text(json.dumps(cfg, indent=2) + "\n")
    guide = Path("GUARD_SETUP.md")
    if not guide.exists():
        guide.write_text(GUIDE)
    if url:
        print(f"wrote guard.config.json for {cfg['base_url']} and GUARD_SETUP.md (how to create the two test users).\n"
              "Next: follow GUARD_SETUP.md, then set \"setup_complete\": true. Live scans are refused until you do.\n"
              "Code-only scans work right away: guard scan --no-live")
    else:
        print("wrote guard.config.json with made-up staging hosts and routes, and GUARD_SETUP.md.\n"
              "Put your real staging url in base_url and allowed_hosts (or re-run `guard init --base-url URL`), then "
              "set \"setup_complete\": true. Live scans are refused until you do.\n"
              "Code-only scans work right away: guard scan --no-live")
    return EXIT_OK



def cmd_doctor(args) -> int:
    """What is installed, what is configured, and what is missing. Changes nothing and sends nothing."""
    import shutil

    if args.explain:
        print(explain.explain(args.explain))
        return 0
    if args.install is not None:
        try:
            results = scanners.install(args.lock, only=args.install or None)
        except scanners.LockError as e:
            print(f"install: {e}", file=sys.stderr)
            return EXIT_CONFIG
        for tool, status, detail in results:
            print(f"  {tool:9} {status.upper():9} {detail}")
        print(f"\nInstalled tools go in {scanners.tools_dir()} and are found automatically by `guard scan`.")
        return 1 if any(st in ("refused", "failed") for _, st, _ in results) else 0

    print("guard doctor\n")
    print("Scanners (without one, its kind of problem is not looked for, the scan is PARTIAL and `guard scan` exits 4):")
    for tool, what in TOOLS.items():
        path = shutil.which(tool, path=scanners.search_path())
        print(f"  {tool:9} {what:16} " + (f"installed ({path})" if path else f"MISSING. Install: {INSTALL_HINT[tool]}"))
    lock = Path(args.lock).exists()
    print("  guard never picks scanner versions or checksums. To install gitleaks and trivy from versions you pinned:\n"
          f"  write {args.lock} (see scanners.lock.example, {'found' if lock else 'not found yet'}), then `guard doctor --install`.\n"
          "  semgrep is a Python package: install it yourself with a pinned `pip install --require-hashes`.\n")
    if not Path(args.config).exists():
        print(f"Config: {args.config} not found. Run `guard init`. Code-only scans (guard scan --no-live) work without it.")
        return 0
    try:
        cfg = Config.load(args.config)
    except (OSError, ValueError) as e:
        print(f"Config: {args.config} has an error: {e}", file=sys.stderr)
        return 2
    why = cfg.live_blocker()
    print(f"Config: {args.config}")
    print(f"  live scans: " + ("ready" if not why else f"REFUSED. {why}"))
    print(f"  allowed_hosts: {', '.join(cfg.allowed_hosts) or 'none'}")
    tokens = [("tenant_a_token", cfg.tenant_a_token), ("tenant_b_token", cfg.tenant_b_token),
              *sorted(cfg.tokens.items())]
    print("  tokens: " + ", ".join(f"{n} {'set' if v else 'NOT SET'}" for n, v in tokens))
    if cfg.accepted_risks:
        print(f"  accepted risks: {len(cfg.accepted_risks)}")
    print("\nChecks (what a full scan would do with this config):")
    ready = {
        "static": ("see scanners above", all(shutil.which(t) for t in TOOLS)),
        "tenant": ("needs tenant_a_token, tenant_b_token, tenant_a_resources",
                   bool(cfg.tenant_a_token and cfg.tenant_b_token and cfg.tenant_a_resources)),
        "access": ("needs access_checks (and a token per caller)", bool(cfg.access_checks)),
        "injection": ("needs injection_params or injection_targets", bool(cfg.injection_params or cfg.injection_targets)),
        "mass_assignment": ("needs mass_assignment_targets", bool(cfg.mass_assignment_targets)),
        "upload": ("needs upload_path", bool(cfg.upload_path)),
        "ratelimit": ("needs rate_limit_path", bool(cfg.rate_limit_path)),
        "ai probes": ("needs ai_endpoint and ai_canaries", bool(cfg.ai_endpoint.get("path") and cfg.ai_canaries)),
        "headers/cors/cookies": ("needs probe_paths", bool(cfg.probe_paths)),
        "tenant_routes": ("needs the tenant settings plus an OpenAPI schema (openapi_path / openapi_file)",
                          bool(cfg.tenant_a_token and cfg.tenant_b_token and cfg.tenant_a_resources)),
        "supabase_audit": ("needs supabase/config.toml, supabase_advisors_file or db_audit_url",
                           bool(cfg.supabase_advisors_file or cfg.db_audit_url)),
    }
    for name, (need, ok) in ready.items():
        print(f"  {name:22} " + ("configured" if ok else f"NOT CONFIGURED ({need})"))
    if len(cfg.probe_paths) > cfg.max_probe_paths:
        print(f"  note: only the first {cfg.max_probe_paths} of {len(cfg.probe_paths)} probe_paths are checked "
              "(max_probe_paths)")
    ready = readiness.items(cfg.launch_signoffs)
    print(f"\nLaunch readiness: {readiness.status_line(ready)}")
    for i in ready:
        print(f"  [{'signed off' if i.signed_off else 'OPEN'}] {i.title}")
    print("\nMore detail on any check: guard doctor --explain <check>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
