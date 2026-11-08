"""Wrappers around well-known open-source scanners. They run locally, if
installed, and their JSON output is normalized into Findings. Nothing is
downloaded or executed implicitly: missing tools are reported, not fetched."""
from __future__ import annotations

import json
import shutil
import subprocess

from .findings import Finding

SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _run(cmd: list[str], ok_codes=(0, 1)) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return p.returncode in ok_codes, p.stdout


def parse_semgrep(raw: str) -> list[Finding]:
    out = []
    for r in json.loads(raw or "{}").get("results", []):
        sev = SEMGREP_SEV.get(r.get("extra", {}).get("severity", "INFO"), "low")
        loc = f"{r.get('path')}:{r.get('start', {}).get('line')}"
        out.append(Finding("semgrep", sev, r.get("check_id", "semgrep rule"),
                           r.get("extra", {}).get("message", ""), loc, tags=["sast"]))
    return out


def parse_gitleaks(raw: str) -> list[Finding]:
    out = []
    for r in json.loads(raw or "[]") or []:
        out.append(Finding("gitleaks", "high", f"Secret in repo: {r.get('RuleID')}",
                           r.get("Description", ""), f"{r.get('File')}:{r.get('StartLine')}",
                           fix="Rotate the secret, remove it from history, load it from env/secret manager.",
                           tags=["secrets"]))
    return out


def parse_trivy(raw: str) -> list[Finding]:
    out = []
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    for res in json.loads(raw or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.append(Finding("trivy", sev_map.get(v.get("Severity"), "low"),
                               f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                               v.get("Title", ""), res.get("Target", ""),
                               fix=f"Upgrade to {v.get('FixedVersion')}" if v.get("FixedVersion") else "",
                               tags=["dependencies"]))
    return out


def run_all(source_dir: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    if shutil.which("semgrep"):
        ok, out = _run(["semgrep", "scan", "--config", "p/owasp-top-ten", "--json", "--quiet", source_dir])
        if ok:
            findings += parse_semgrep(out)
        else:
            notes.append("semgrep failed to run (SAST skipped)")
    else:
        notes.append("semgrep not installed (SAST skipped)")
    if shutil.which("gitleaks"):
        ok, out = _run(["gitleaks", "detect", "--source", source_dir, "--no-banner",
                        "--report-format", "json", "--report-path", "/dev/stdout"])
        if ok:
            findings += parse_gitleaks(out)
        else:
            notes.append("gitleaks failed to run (secret scan skipped)")
    else:
        notes.append("gitleaks not installed (secret scan skipped)")
    if shutil.which("trivy"):
        ok, out = _run(["trivy", "fs", "--format", "json", "--quiet", source_dir], ok_codes=(0,))
        if ok:
            findings += parse_trivy(out)
        else:
            notes.append("trivy failed to run (dependency scan skipped)")
    else:
        notes.append("trivy not installed (dependency scan skipped)")
    return findings, notes
