"""Wrappers around well-known open-source scanners. They run locally, if
installed, and their JSON output is normalized into Findings. Nothing is
downloaded or executed implicitly: missing tools are reported, not fetched."""
from __future__ import annotations

import json
import shutil
import subprocess

from .coverage import RAN, SKIPPED, TOOLS, Coverage
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


INSTALL_HINT = {
    "semgrep": "pip install semgrep   (https://semgrep.dev/docs/getting-started/)",
    "gitleaks": "https://github.com/gitleaks/gitleaks#installing",
    "trivy": "https://trivy.dev/latest/getting-started/installation/",
}


def scan_tools(source_dir: str) -> tuple[list[Finding], list[Coverage]]:
    """Run each installed scanner and say, per scanner, whether it ran. A missing scanner is a coverage gap:
    without gitleaks there was no secret scan, and a report must not read as clean in that case."""
    findings: list[Finding] = []
    cov: list[Coverage] = []
    plans = [
        ("semgrep", ["semgrep", "scan", "--config", "p/owasp-top-ten", "--json", "--quiet", source_dir],
         (0, 1), parse_semgrep),
        ("gitleaks", ["gitleaks", "detect", "--source", source_dir, "--no-banner",
                      "--report-format", "json", "--report-path", "/dev/stdout"], (0, 1), parse_gitleaks),
        ("trivy", ["trivy", "fs", "--format", "json", "--quiet", source_dir], (0,), parse_trivy),
    ]
    for tool, cmd, ok_codes, parse in plans:
        what = TOOLS[tool]
        if not shutil.which(tool):
            cov.append(Coverage(f"{tool} ({what})", SKIPPED, f"not installed; run `guard doctor`"))
            continue
        ok, out = _run(cmd, ok_codes=ok_codes)
        if not ok:
            cov.append(Coverage(f"{tool} ({what})", SKIPPED, "installed but failed to run"))
            continue
        try:
            findings += parse(out)
        except ValueError:
            cov.append(Coverage(f"{tool} ({what})", SKIPPED, "ran, but its output could not be read"))
            continue
        cov.append(Coverage(f"{tool} ({what})", RAN))
    return findings, cov


def run_all(source_dir: str) -> tuple[list[Finding], list[str]]:
    """Findings plus plain notes. Kept for callers that only want strings; `scan_tools` has the detail."""
    findings, cov = scan_tools(source_dir)
    notes = [f"{c.name.split(' ')[0]} {c.detail} ({c.name.split('(')[-1].rstrip(')')} skipped)"
             for c in cov if c.status == SKIPPED]
    return findings, notes
