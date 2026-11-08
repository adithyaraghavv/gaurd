from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, report
from .checks import ALL_CHECKS, OFFLINE_OK
from .config import DEFAULT_CONFIG, Config
from .loop import decide, record_run, write_fix_tasks, write_summary
from .runners import run_all
from .scope import Scope, ScopeError, ScopedHTTP


def _run_stages(cfg: Config, stages: set[str], http):
    findings, notes = [], []
    if "static" in stages:
        f, n = run_all(cfg.source_dir)
        findings += f
        notes += n
    for name, fn in ALL_CHECKS.items():
        if name not in stages:
            continue
        if http is None and name not in OFFLINE_OK:
            continue
        findings += fn(cfg, http)  # ScopeError propagates to the caller
    return findings, notes


def _finish(cfg: Config, findings, notes, out_dir: str) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(report.to_markdown(findings, notes))
    (out / "report.json").write_text(report.to_json(findings, notes))
    (out / "report.sarif").write_text(report.to_sarif(findings))
    result = record_run(out_dir, findings, cfg.fail_on)
    write_fix_tasks(out_dir, result)
    if result["seen_total"]:
        write_summary(out_dir, result, cfg.fail_on)
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
    state_path = out / "gate_state.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    if not state and not _has_changes():
        return 0
    try:
        cfg = Config.load(args.config) if Path(args.config).exists() else Config()
    except (OSError, ValueError) as e:
        print(f"guard gate: config error: {e}", file=sys.stderr)
        return 0
    stages = set(ALL_CHECKS) | {"static"}
    findings, notes = _run_stages(cfg, stages, None)  # offline only: static + code checks
    result = _finish(cfg, findings, notes, args.out)
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

    args = p.parse_args(argv)

    if args.cmd == "init":
        dest = Path("guard.config.json")
        if dest.exists():
            print("guard.config.json already exists", file=sys.stderr)
            return 2
        dest.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        print("wrote guard.config.json; edit it before scanning")
        return 0

    if args.cmd == "gate":
        return cmd_gate(args)

    try:
        cfg = Config.load(args.config)
    except (OSError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    stages = set(args.only) if args.only else {"static", *ALL_CHECKS}
    http = None if args.no_live else ScopedHTTP(Scope(cfg.allowed_hosts, cfg.allow_production))
    try:
        findings, notes = _run_stages(cfg, stages, http)
    except ScopeError as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return 3

    result = _finish(cfg, findings, notes, args.out)
    print(f"{len(findings)} findings, {len(result['blocking'])} blocking; reports in {args.out}/ "
          f"(fix list: {args.out}/fix_tasks.md)")
    return 1 if result["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
