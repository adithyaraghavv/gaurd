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


def percent(coverage: list[Coverage]) -> int | None:
    """Share of applicable checks that actually ran. `n/a` (nothing to check) is left out. None if nothing applies."""
    counted = [c for c in coverage if c.status != NA]
    if not counted:
        return None
    return round(100 * sum(1 for c in counted if c.status == RAN) / len(counted))


def counts(coverage: list[Coverage], scanner_names: set[str]) -> dict:
    """Numbers for the one-line result. "Scanner checks" are the ones that need no network (the outside scanners
    and the code/config checks); "live" are the ones that talk to a running staging app."""
    def is_scanner(c: Coverage) -> bool:
        return c.name.split(" ")[0] in scanner_names
    sc = [c for c in coverage if is_scanner(c) and c.status != NA]
    live = [c for c in coverage if not is_scanner(c) and c.status != NA]
    return {
        "scanner_total": len(sc),
        "scanner_missing": [c for c in sc if c.status != RAN],
        "live_total": len(live),
        "live_off": [c for c in live if c.status == OFF],
        "live_skipped": [c for c in live if c.status == SKIPPED],
        "live_ran": [c for c in live if c.status == RAN],
    }


def result_line(coverage: list[Coverage], scanner_names: set[str], total: int, blocking: int,
                accepted: int = 0) -> str:
    """The first thing a human reads. A partial scan must never read like a pass, so it says PARTIAL, what did
    not run, and that the findings count only describes what did."""
    c = counts(coverage, scanner_names)
    pct = percent(coverage)
    parts = []
    if c["scanner_missing"]:
        parts.append(f"{len(c['scanner_missing'])} of {c['scanner_total']} scanner checks did not run "
                     f"({', '.join(x.name.split(' ')[0] for x in c['scanner_missing'])})")
    if c["live_off"]:
        parts.append(f"{len(c['live_off'])} live checks off")
    if c["live_skipped"]:
        parts.append(f"{len(c['live_skipped'])} live checks skipped (not configured)")
    cov = f"coverage {pct}%" if pct is not None else "coverage n/a"
    findings = f"{total} finding(s) in the checks that ran"
    extra = f", {accepted} accepted" if accepted else ""
    if blocking:
        head = f"FAIL: {blocking} blocking finding(s) ({findings}{extra})"
        return head + (f". PARTIAL: {'; '.join(parts)}; {cov}" if parts else f"; {cov}")
    if parts:
        return f"PARTIAL: {'; '.join(parts)}; {cov}. {findings}{extra}. This is NOT a pass."
    return f"COMPLETE: every applicable check ran; {cov}. {findings}{extra}."


def required_missing(coverage: list[Coverage]) -> list[Coverage]:
    """Required scanners that did not run: the outside scanners (code, secret, dependency scan) that were
    wanted but are missing or failed. Checks switched off on purpose (--no-live, --only) do not count."""
    return [c for c in coverage if c.status == SKIPPED and c.name.split(" ")[0] in TOOLS]
