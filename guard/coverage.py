"""What actually ran. A scan that skipped a check must say so; "clean" only means something for the checks
that ran, so the report and summary both open with this table."""
from __future__ import annotations

from dataclasses import asdict, dataclass

RAN, SKIPPED, OFF, NA = "ran", "skipped", "off", "n/a"
LABEL = {RAN: "ran", SKIPPED: "SKIPPED", OFF: "off (by choice)", NA: "not applicable"}

# Static scanners and what each one covers, in words a non-specialist understands.
TOOLS = {"semgrep": "code scan", "gitleaks": "secret scan", "trivy": "dependency scan"}


class Skipped(Exception):
    """Raised by a check that cannot run, so the report says so instead of the check silently producing nothing.

    `applicable=False` means there was nothing to check (a project with no .sql files), which does not make
    a scan incomplete. The default means the check should have run but could not (not configured, no token)."""

    def __init__(self, reason: str, applicable: bool = True):
        super().__init__(reason)
        self.reason, self.applicable = reason, applicable


@dataclass
class Coverage:
    name: str
    status: str  # ran | skipped (needs attention) | off (you chose this) | n/a (nothing to check)
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def gaps(coverage: list[Coverage]) -> list[Coverage]:
    """Checks that did not run and should have. `off` (--no-live, --only) and `n/a` do not count."""
    return [c for c in coverage if c.status == SKIPPED]


def is_complete(coverage: list[Coverage]) -> bool:
    return not gaps(coverage)


def to_markdown_table(coverage: list[Coverage]) -> list[str]:
    if not coverage:
        return []
    lines = ["## What ran", "", "| check | status | detail |", "|---|---|---|"]
    for c in coverage:
        lines.append(f"| {c.name} | {LABEL.get(c.status, c.status)} | {c.detail.replace('|', '/')} |")
    return lines + [""]
