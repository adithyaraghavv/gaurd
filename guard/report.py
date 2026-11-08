from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Finding, SEVERITIES, severity_rank


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -severity_rank(f.severity))


def to_markdown(findings: list[Finding], notes: list[str]) -> str:
    fs = sort_findings(findings)
    counts = {s: sum(1 for f in fs if f.severity == s) for s in reversed(SEVERITIES)}
    lines = ["# Guard report", f"_{datetime.now(timezone.utc).isoformat(timespec='seconds')}_", "",
             "| " + " | ".join(counts) + " |", "|" + "---|" * len(counts),
             "| " + " | ".join(str(v) for v in counts.values()) + " |", ""]
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


def to_json(findings: list[Finding], notes: list[str]) -> str:
    return json.dumps({"notes": notes, "findings": [f.to_dict() for f in sort_findings(findings)]}, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    results = [{"ruleId": f.check, "level": lvl[f.severity], "message": {"text": f"{f.title}: {f.detail}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target or "unknown"}}}]}
               for f in sort_findings(findings)]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "guard"}}, "results": results}]}, indent=2)


def exceeds(findings: list[Finding], fail_on: str) -> bool:
    return any(severity_rank(f.severity) >= severity_rank(fail_on) for f in findings)
