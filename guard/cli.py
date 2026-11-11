from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, accept, report
from .checks import ALL_CHECKS, OFFLINE_OK, PROBE_PATH_CHECKS
from .claude_setup import install
from .config import DEFAULT_CONFIG, Config
from .coverage import NA, OFF, RAN, SKIPPED, TOOLS, Coverage, Skipped
from .loop import decide, record_run, write_fix_tasks, write_summary
from .runners import INSTALL_HINT, scan_tools
from .scope import Scope, ScopeError, ScopedHTTP


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
        try:
            found = fn(cfg, http)  # ScopeError propagates to the caller
        except Skipped as e:
            coverage.append(Coverage(name, SKIPPED if e.applicable else NA, e.reason))
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
    (out / "report.md").write_text(report.to_markdown(findings, notes, coverage, accepted))
    (out / "report.json").write_text(report.to_json(findings, notes, coverage, accepted))
    (out / "report.sarif").write_text(report.to_sarif(findings))
    result = record_run(out_dir, findings, cfg.fail_on, coverage, accepted, notes)
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

    g = sub.add_parser("gate", help="Claude Code Stop hook: block stopping until issues are fixed")
    g.add_argument("-c", "--config", default="guard.config.json")
    g.add_argument("-o", "--out", default="guard_out")

    sub.add_parser("init", help="write a starter guard.config.json")

    d = sub.add_parser("doctor", help="show what is installed, configured and missing")
    d.add_argument("-c", "--config", default="guard.config.json")

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
        dest = Path("guard.config.json")
        if dest.exists():
            print("guard.config.json already exists", file=sys.stderr)
            return 2
        dest.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        print("wrote guard.config.json with made-up staging hosts and routes.\n"
              "Edit it, then set \"setup_complete\": true. Live scans are refused until you do.\n"
              "Code-only scans work right away: guard scan --no-live")
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

    stages = set(args.only) if args.only else {"static", *ALL_CHECKS}
    wants_live = not args.no_live and any(st not in OFFLINE_OK | {"static"} for st in stages)
    if wants_live and (why := cfg.live_blocker()):
        # Nothing has been sent. The starter config names a host you do not control, so a live scan is refused
        # until you have reviewed it.
        print(f"LIVE SCAN REFUSED: {why}\nCode-only checks still work: guard scan --no-live", file=sys.stderr)
        return 3
    http = None if args.no_live else ScopedHTTP(Scope(cfg.allowed_hosts, cfg.allow_production))
    try:
        findings, notes, coverage, accepted = _run_stages(cfg, stages, http)
    except ScopeError as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return 3

    result = _finish(cfg, findings, notes, args.out, coverage, accepted)
    line = (f"{len(findings)} findings, {len(result['blocking'])} blocking; reports in {args.out}/ "
            f"(fix list: {args.out}/fix_tasks.md)")
    if accepted:
        line += f"; {len(accepted)} accepted risk(s) listed separately"
    print(line)
    if result["gaps"]:
        print(f"WARNING: {len(result['gaps'])} check(s) did not run, so this is not a full clean: "
              + ", ".join(c.name for c in result["gaps"]) + f". See {args.out}/summary.md or run `guard doctor`.")
    return 1 if result["blocking"] else 0


def cmd_doctor(args) -> int:
    """What is installed, what is configured, and what is missing. Changes nothing and sends nothing."""
    import shutil

    print("guard doctor\n")
    print("Scanners (optional; without one, its kind of problem is not looked for and reports say so):")
    for tool, what in TOOLS.items():
        path = shutil.which(tool)
        print(f"  {tool:9} {what:16} " + (f"installed ({path})" if path else f"MISSING. Install: {INSTALL_HINT[tool]}"))
    print("  guard does not download scanners for you: a pinned, checksum-verified installer needs checksums\n"
          "  that only you should vouch for. Pin the version you install and verify it yourself.\n")
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
    }
    for name, (need, ok) in ready.items():
        print(f"  {name:22} " + ("configured" if ok else f"NOT CONFIGURED ({need})"))
    if len(cfg.probe_paths) > cfg.max_probe_paths:
        print(f"  note: only the first {cfg.max_probe_paths} of {len(cfg.probe_paths)} probe_paths are checked "
              "(max_probe_paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
