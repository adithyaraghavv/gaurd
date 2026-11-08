"""Text that `guard setup` installs for Claude Code. Kept in code so it works
after a normal pip install (no data files to lose)."""
from __future__ import annotations

_HEAD = """---
description: Full bug and security check, fix everything, re-test until clean, then summarize
---

Run guard's full quality and security loop on this repo. Maximum 5 rounds.

First-time setup in this repo (skip any step that is already done):
"""

_INSTALL_PLAIN = """1. Run `guard --version`. If the command is not found, stop and tell me to install
   guard (`pip install` it from my guard repo), then try again.
"""

_INSTALL_FROM_REPO = """1. Run `guard --version`. If the command is not found, install guard from my repo
   `{repo}` (private; read access only):
   a. If you have an `add_repo` tool, use it to add `{repo}` to this session (read access).
   b. Run `git clone --depth 1 https://github.com/{repo} /tmp/guard-src`
   c. Run `pip install /tmp/guard-src` (add `--break-system-packages` if pip refuses).
   d. Run `guard --version` to confirm. If any step fails, stop and tell me exactly what failed.
"""

_REST = """2. If `guard.config.json` does not exist, run `guard init`.
3. Make sure `.gitignore` contains the lines `guard_out/` and `guard.config.json`.
   Add any that are missing.

Round 0: review only the changed code, to save usage. Use `git diff` against the main branch
(or `git diff HEAD~5` / the files changed on this branch if there is no main). Look for bugs,
unhandled errors, edge cases, missing input validation and authorization gaps
(data not scoped to the caller, missing auth checks, client-trusted ids). Fix what you find.
If there is no diff to review, do NOT read the whole codebase; rely on the scan and tell me
I can ask for a full review. Do not run the project's full test suite unless you changed code.

Then repeat until clean:
1. Run `guard scan --no-live`. Only run live checks (`guard scan`) if
   `guard.config.json` points at a staging host that I have confirmed is safe.
   Never target production.
2. Read `guard_out/fix_tasks.md`.
3. If there are no blocking issues, stop the loop.
4. Otherwise fix every blocking issue at its root cause. Do not edit guard,
   its config or scope, and do not add ignore comments to hide findings.
5. Go back to step 1 so the fixes are tested again.

Stop early if a round fixes nothing (no progress) or after 5 rounds.

Finish with a plain-English summary for me (use `guard_out/summary.md`):
- what was found, and how serious
- what you changed to fix each issue
- how many rounds it took and whether the final scan is clean
- anything still open, and why, with your recommendation
- what could not be verified
"""


def command_md(repo: str | None = None) -> str:
    """The /guard command text. With `repo` (owner/name), the command can install
    guard itself in cloud sessions where it is not preinstalled."""
    install = _INSTALL_FROM_REPO.format(repo=repo) if repo else _INSTALL_PLAIN
    return _HEAD + install + _REST


COMMAND_MD = command_md()

RULES_START = "<!-- guard:rules:start -->"
RULES_END = "<!-- guard:rules:end -->"

RULES_MD = f"""{RULES_START}
## Quality and security rules (from guard)

- Before saying a task is done: review the changed code for bugs, error handling,
  edge cases and security issues, and fix what you find.
- If a guard Stop hook blocks you, read `guard_out/fix_tasks.md`, fix every issue at
  its root cause, and keep going until the check passes. Never edit guard, its config
  or its scope, and never add ignore comments just to hide a finding. If something is
  a false positive, say so and explain why.
- When the check passes after fixes, give the user a plain-English summary using
  `guard_out/summary.md`: what was found, what you changed for each issue, how many
  rounds it took, what is left for them to decide, what you could not verify.
- Any data that belongs to a user, account, team or organization must be filtered by
  the caller's identity on the server. Never trust ids sent by the client.
- Database access: parameterized queries / ORM bindings only; never build SQL from
  strings. If using row-level security, keep it enabled on every table.
- Validate all input on the server. Return generic error messages; no stack traces.
- Secrets come from environment variables, never from code or committed files.
- Never run live checks against production. Staging with dummy data only.
{RULES_END}
"""

HOOK_COMMAND = "guard gate"
HOOK_ENTRY = {"hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 600}]}

GITIGNORE_LINES = ["guard_out/", "guard.config.json"]
