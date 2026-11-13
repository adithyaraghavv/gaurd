"""Launch readiness: the manual items no scanner can verify.

Guard never marks these as passed. They stay open, and the overall launch status stays NOT READY, until the
project owner signs each one off in `launch_signoffs` in the config (who, when, optional note and expiry). A
sign-off is the owner's statement, not guard's finding, and the report says so. The coding agent is told not
to add sign-offs itself."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

ITEMS: dict[str, tuple[str, str]] = {
    "independent_review": (
        "Independent human review or penetration test",
        "Someone other than the author (or the coding agent) has reviewed the code and the deployed app, or a "
        "pen test has been done. Scanners catch common mistakes, not business-logic flaws."),
    "error_alerts": (
        "Error alerts reach a person",
        "When the live app errors, crashes or is attacked, a named person is notified (not just a log nobody reads)."),
    "backups_restore": (
        "Backups are on and a restore has been tested",
        "Backups exist AND someone has restored one into a scratch environment and checked the data."),
    "incident_plan": (
        "Written incident plan",
        "Who does what in the first hour of an incident: who decides, who fixes, who talks to users."),
    "breach_contacts": (
        "Who to notify if data leaks",
        "A written list of who must be told (affected users, any regulator, payment and platform providers) and how "
        "to reach them."),
}


@dataclass
class Item:
    id: str
    title: str
    detail: str
    signed_off: bool
    by: str = ""
    on: str = ""
    note: str = ""
    expired: bool = False


def validate(raw: dict | None) -> dict:
    """Return cleaned sign-offs or raise ValueError saying which one is wrong."""
    clean: dict = {}
    for key, entry in (raw or {}).items():
        if key not in ITEMS:
            raise ValueError(f"launch_signoffs has unknown item '{key}'; use one of {sorted(ITEMS)}")
        if not isinstance(entry, dict):
            raise ValueError(f"launch_signoffs['{key}'] must be an object")
        unknown = set(entry) - {"by", "date", "note", "expires"}
        if unknown:
            raise ValueError(f"launch_signoffs['{key}'] has unknown keys {sorted(unknown)}")
        for need in ("by", "date"):
            if not str(entry.get(need, "")).strip():
                raise ValueError(f"launch_signoffs['{key}'] needs '{need}' (who signed off, and when)")
        for dkey in ("date", "expires"):
            val = str(entry.get(dkey, "") or "").strip()
            if val:
                try:
                    date.fromisoformat(val)
                except ValueError as ex:
                    raise ValueError(f"launch_signoffs['{key}'] '{dkey}' must be YYYY-MM-DD") from ex
        clean[key] = {k: str(entry.get(k, "") or "").strip() for k in ("by", "date", "note", "expires")}
    return clean


def items(signoffs: dict | None, today: date | None = None) -> list[Item]:
    today = today or date.today()
    out = []
    for key, (title, detail) in ITEMS.items():
        s = (signoffs or {}).get(key)
        if not s:
            out.append(Item(key, title, detail, False))
            continue
        lapsed = bool(s["expires"]) and date.fromisoformat(s["expires"]) < today
        out.append(Item(key, title, detail, not lapsed, s["by"], s["date"], s["note"], lapsed))
    return out


def is_ready(its: list[Item]) -> bool:
    return all(i.signed_off for i in its)


def status_line(its: list[Item]) -> str:
    open_n = sum(1 for i in its if not i.signed_off)
    if open_n:
        return f"NOT READY TO LAUNCH. {open_n} of {len(its)} manual item(s) are still open."
    return ("ALL MANUAL ITEMS SIGNED OFF by the owner. Guard cannot verify them; the scan result above is "
            "separate and only covers the automated checks.")


def to_markdown(its: list[Item]) -> list[str]:
    lines = ["## Launch readiness: manual items", "",
             f"**{status_line(its)}**", "",
             "Guard cannot check these and never marks them as passed. Only the project owner can sign one off, "
             "in `launch_signoffs` in guard.config.json.", ""]
    for i in its:
        if i.signed_off:
            extra = f" ({i.note})" if i.note else ""
            lines.append(f"- [signed off by {i.by} on {i.on}; not verified by guard] **{i.title}**{extra}")
        else:
            why = " Sign-off expired." if i.expired else ""
            lines.append(f"- [ ] **{i.title}**.{why} {i.detail}")
    return lines + [""]


def to_json(its: list[Item]) -> dict:
    return {"ready": is_ready(its), "status": status_line(its),
            "items": [{"id": i.id, "title": i.title, "signed_off": i.signed_off, "by": i.by, "date": i.on,
                       "expired": i.expired} for i in its]}
