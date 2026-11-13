"""Installing the outside scanners (gitleaks, trivy) from versions YOU pinned.

Guard never decides which version to install, where to get it, or what its checksum should be. You write
`scanners.lock` once, after checking the release yourself:

  {"tools": {"gitleaks": {"version": "8.x.y", "platforms": {
      "linux-amd64": {"url": "https://github.com/.../gitleaks_8.x.y_linux_x64.tar.gz",
                      "sha256": "<64 hex characters>", "binary": "gitleaks"}}}}}

`guard doctor --install` then downloads exactly those URLs over https, checks every download against the SHA-256 in
the file, and refuses (and deletes the download) on any mismatch, any placeholder, any tool or platform that is not
in the file. Only the one named binary is taken from an archive; nothing else is extracted.

semgrep is a Python package, not a single binary, so it is not handled here: install it with your own pinned
`pip install --require-hashes -r requirements.txt`."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_BYTES = 300_000_000
INSTALLABLE = ("gitleaks", "trivy")  # single-binary tools; semgrep is installed with pip


class LockError(Exception):
    pass


def tools_dir() -> Path:
    return Path(os.environ.get("GUARD_TOOLS_DIR") or Path.home() / ".guard" / "bin")


def search_path() -> str:
    """PATH with guard's own tools directory first, so an installed scanner is found."""
    return os.pathsep.join([str(tools_dir()), os.environ.get("PATH", "")])


def platform_key() -> str:
    system = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    return f"{system}-{arch}"


def load_lock(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise LockError(f"{path} not found. Create it from scanners.lock.example after checking each release "
                        "yourself; guard will not choose versions or checksums for you.")
    try:
        data = json.loads(p.read_text())
    except ValueError as e:
        raise LockError(f"{path} is not valid JSON: {e}") from e
    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise LockError(f"{path} needs a non-empty \"tools\" object")
    return tools


def check_entry(tool: str, entry: dict, plat: str) -> dict:
    """Return the platform entry, or raise LockError saying exactly what is missing or unsafe."""
    version = str(entry.get("version", "")).strip()
    if not version or version.upper().startswith("REPLACE"):
        raise LockError(f"{tool}: 'version' is empty or still a placeholder")
    plats = entry.get("platforms")
    if not isinstance(plats, dict) or plat not in plats:
        raise LockError(f"{tool}: no entry for this platform ({plat}); guard will not guess one. "
                        f"Listed: {sorted(plats or {})}")
    e = plats[plat]
    if not isinstance(e, dict):
        raise LockError(f"{tool}: the {plat} entry must be an object with url, sha256 and binary")
    url = str(e.get("url", ""))
    if not url.startswith("https://"):
        raise LockError(f"{tool}: url must start with https://")
    sha = str(e.get("sha256", "")).lower()
    if not SHA256.match(sha):
        raise LockError(f"{tool}: sha256 must be 64 hex characters (is it still a placeholder?)")
    if not str(e.get("binary", "")).strip() or "/" in e["binary"] or "\\" in e["binary"] or e["binary"].startswith("."):
        raise LockError(f"{tool}: 'binary' must be the plain file name to take from the download")
    return {"version": version, "url": url, "sha256": sha, "binary": e["binary"]}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guard-installer"})
    with urllib.request.urlopen(req, timeout=120) as r:  # https only; proxies honoured from the environment
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise LockError("download is larger than the safety limit")
    return data


def _extract(data: bytes, url: str, binary: str) -> bytes:
    """The bytes of the one named binary. Archives are read member by member; nothing is written by an archive."""
    name = url.split("?")[0].lower()
    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            for m in t.getmembers():
                if m.isfile() and Path(m.name).name == binary:
                    if m.size > MAX_BYTES:
                        raise LockError("the file inside the archive is larger than the safety limit")
                    f = t.extractfile(m)
                    if f:
                        return f.read()
    elif name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if not n.endswith("/") and Path(n).name == binary:
                    if z.getinfo(n).file_size > MAX_BYTES:
                        raise LockError("the file inside the archive is larger than the safety limit")
                    return z.read(n)
    else:  # a bare binary
        return data
    raise LockError(f"'{binary}' was not found inside the download")


def install(lock_path: str, only: list[str] | None = None, dest: Path | None = None, getter=fetch,
            plat: str | None = None) -> list[tuple[str, str, str]]:
    """Install every tool in the lock (or `only`). Returns [(tool, status, detail)]. `getter` is injectable so the
    verification can be tested without a network."""
    tools = load_lock(lock_path)
    dest = dest or tools_dir()
    plat = plat or platform_key()
    out: list[tuple[str, str, str]] = []
    wanted = only or list(tools)
    for tool in wanted:
        if tool == "semgrep":
            out.append((tool, "skipped", "semgrep is a Python package: install it with your own pinned "
                                         "`pip install --require-hashes`"))
            continue
        if tool not in INSTALLABLE:
            out.append((tool, "refused", f"{tool} is not a tool guard installs (only {', '.join(INSTALLABLE)})"))
            continue
        if tool not in tools:
            out.append((tool, "refused", "not in the lock file; guard will not pick a version itself"))
            continue
        try:
            e = check_entry(tool, tools[tool], plat)
            data = getter(e["url"])
            digest = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(digest, e["sha256"]):
                raise LockError(f"checksum MISMATCH (lock says {e['sha256'][:12]}..., download is {digest[:12]}...). "
                                "Nothing was installed.")
            binary = _extract(data, e["url"], e["binary"])
        except LockError as err:
            out.append((tool, "refused", str(err)))
            continue
        except Exception as err:  # network failure and the like: report, install nothing
            out.append((tool, "failed", f"could not download: {type(err).__name__}"))
            continue
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / e["binary"]
        tmp = dest / f".{e['binary']}.partial"
        tmp.write_bytes(binary)
        tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        tmp.replace(target)
        out.append((tool, "installed", f"{e['version']} from the lock file -> {target}"))
    return out


def installed_version(tool: str) -> str:
    """First line of `tool --version`, or ''. Informational only."""
    import shutil
    exe = shutil.which(tool, path=search_path())
    if not exe:
        return ""
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr).strip() else ""
