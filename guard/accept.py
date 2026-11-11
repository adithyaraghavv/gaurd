"""Accepted risks: the honest way to deal with a known false alarm or a deliberate choice.

An entry in `accepted_risks` (in guard.config.json) says "I looked at this finding, here is why it is fine, and
here is who answers for it". The finding stops blocking, but it is never hidden: reports list every accepted
risk in its own section with its reason, owner and expiry. Expired entries stop applying and the finding blocks
again. Only the owner of the project should add entries; the coding agent is told not to."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatchcase

from .findings import Finding


@dataclass
class Accepted:
    finding: Finding
    reason: str
    owner: str
    expires: str  # ISO date or ""


def validate(entries: list) -> list[dict]:
    """Return cleaned entries, or raise ValueError with a message that says which entry is wrong."""
    clean = []
    for n, e in enumerate(entries or [], 1):
        where = f"accepted_risks[{n}]"
        if not isinstance(e, dict):
            raise ValueError(f"{where} must be an object")
        unknown = set(e) - {"check", "title", "target", "reason", "owner", "expires"}
        if unknown:
            raise ValueError(f"{where} has unknown keys {sorted(unknown)}")
        for key in ("check", "reason", "owner"):
            if not str(e.get(key, "")).strip():
                raise ValueError(f"{where} needs a non-empty '{key}'")
        if not (str(e.get("title", "")).strip() or str(e.get("target", "")).strip()):
            raise ValueError(f"{where} needs 'title' and/or 'target' so it cannot accept a whole check")
        exp = str(e.get("expires", "") or "").strip()
        if exp:
            try:
                date.fromisoformat(exp)
            except ValueError as ex:
                raise ValueError(f"{where} 'expires' must be YYYY-MM-DD") from ex
        clean.append({k: str(e.get(k, "") or "").strip() for k in ("check", "title", "target", "reason", "owner", "expires")})
    return clean


def _matches(e: dict, f: Finding) -> bool:
    if e["check"].lower() != f.check.lower():
        return False
    if e["title"] and not fnmatchcase(f.title.lower(), e["title"].lower()):
        return False
    if e["target"] and not fnmatchcase(f.target.lower(), e["target"].lower()):
        return False
    return True


def apply(findings: list[Finding], entries: list[dict], today: date | None = None
          ) -> tuple[list[Finding], list[Accepted], list[str]]:
    """Split findings into (still active, accepted) and return notes about stale or expired entries."""
    today = today or date.today()
    active, accepted, notes = [], [], []
    used = [False] * len(entries)
    expired_hit = [False] * len(entries)
    for f in findings:
        hit = None
        for i, e in enumerate(entries):
            if not _matches(e, f):
                continue
            if e["expires"] and date.fromisoformat(e["expires"]) < today:
                expired_hit[i] = True  # matched, but the acceptance has lapsed: the finding counts again
                continue
            hit, used[i] = e, True
            break
        if hit is None:
            active.append(f)
        else:
            accepted.append(Accepted(f, hit["reason"], hit["owner"], hit["expires"]))
    for i, e in enumerate(entries):
        label = f"{e['check']}: {e['title'] or e['target']}"
        if expired_hit[i] and not used[i]:
            notes.append(f"accepted risk expired on {e['expires']} and no longer applies: {label} (owner {e['owner']})")
        elif not used[i]:
            notes.append(f"accepted risk matches nothing (stale? remove it): {label}")
    return active, accepted, notes
