"""`guard setup`: installs the /guard command (and optionally rules and the Stop
hook) for Claude Code, either for your user account or for one project."""
from __future__ import annotations

import json
from pathlib import Path

from .assets import COMMAND_MD, HOOK_COMMAND, HOOK_ENTRY, RULES_MD, RULES_START


def add_hook(settings_path: Path) -> str:
    """Merge the Stop hook into a settings.json without touching anything else."""
    try:
        data = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    except ValueError:
        return f"skipped hook: {settings_path} is not valid JSON (fix it, then re-run)"
    if not isinstance(data, dict):
        return f"skipped hook: {settings_path} has an unexpected format"
    stops = data.setdefault("hooks", {}).setdefault("Stop", [])
    for entry in stops:
        for h in entry.get("hooks", []):
            if h.get("command") == HOOK_COMMAND:
                return f"hook already present in {settings_path}"
    stops.append(HOOK_ENTRY)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2) + "\n")
    return f"added Stop hook to {settings_path}"


def add_rules(path: Path) -> str:
    existing = path.read_text() if path.exists() else ""
    if RULES_START in existing:
        return f"rules already present in {path}"
    path.parent.mkdir(parents=True, exist_ok=True)
    sep = "\n\n" if existing.strip() else ""
    path.write_text(existing.rstrip("\n") + sep + RULES_MD if existing.strip() else RULES_MD)
    return f"added rules to {path}"


def install(claude_dir: Path, rules_path: Path, hook: bool = False, rules: bool = True) -> list[str]:
    done: list[str] = []
    cmd = claude_dir / "commands" / "guard.md"
    cmd.parent.mkdir(parents=True, exist_ok=True)
    cmd.write_text(COMMAND_MD)
    done.append(f"installed /guard command: {cmd}")
    if rules:
        done.append(add_rules(rules_path))
    if hook:
        done.append(add_hook(claude_dir / "settings.json"))
    return done
