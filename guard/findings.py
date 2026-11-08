from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    target: str = ""
    evidence: str = ""
    fix: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity}")

    def to_dict(self) -> dict:
        return asdict(self)


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev)
