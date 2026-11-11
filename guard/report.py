from __future__ import annotations

import json
from datetime import datetime, timezone

from .coverage import Coverage, to_markdown_table
from .findings import Finding, SEVERITIES, severity_rank


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -severity_rank(f.severity))


def accepted_lines(accepted) -> list[str]:
    """Accepted risks get their own section: they stop blocking but are never hidden."""
    if not accepted:
        return []
    lines = [f"## Accepted risks ({len(accepted)}), not counted as open", ""]
    for a in accepted:
        f = a.finding
        until = f"until {a.expires}" if a.expires else "no expiry"
        lines.append(f"- [{f.severity.upper()}] {f.title}" + (f" (`{f.target}`)" if f.target else ""))
        lines.append(f"  - reason: {a.reason}; owner: {a.owner}; {until}")
    return lines + [""]


def to_markdown(findings: list[Finding], notes: list[str], coverage: list[Coverage] | None = None,
                accepted=None) -> str:
    fs = sort_findings(findings)
    counts = {s: sum(1 for f in fs if f.severity == s) for s in reversed(SEVERITIES)}
    lines = ["# Guard report", f"_{datetime.now(timezone.utc).isoformat(timespec='seconds')}_", "",
             "| " + " | ".join(counts) + " |", "|" + "---|" * len(counts),
             "| " + " | ".join(str(v) for v in counts.values()) + " |", ""]
    lines += to_markdown_table(coverage or [])
    lines += accepted_lines(accepted)
    for n in notes:
        lines.append(f"> note: {n}")
    for f in fs:
        lines += ["", f"## [{f.severity.upper()}] {f.title}", f"- check: `{f.check}`"]
        if f.target:
            lines.append(f"- target: `{f.target}`")
        lines.append(f"- {f.detail}")
        if f.evidence:
            lines.append(f"- evidence: `{f.evidence}`")
        if f.fix:
            lines.append(f"- fix: {f.fix}")
    return "\n".join(lines) + "\n"


def to_json(findings: list[Finding], notes: list[str], coverage: list[Coverage] | None = None,
            accepted=None) -> str:
    return json.dumps({
        "notes": notes,
        "coverage": [c.to_dict() for c in coverage or []],
        "accepted": [{"finding": a.finding.to_dict(), "reason": a.reason, "owner": a.owner, "expires": a.expires}
                     for a in accepted or []],
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    results = [{"ruleId": f.check, "level": lvl[f.severity], "message": {"text": f"{f.title}: {f.detail}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target or "unknown"}}}]}
               for f in sort_findings(findings)]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "guard"}}, "results": results}]}, indent=2)


def exceeds(findings: list[Finding], fail_on: str) -> bool:
    return any(severity_rank(f.severity) >= severity_rank(fail_on) for f in findings)
