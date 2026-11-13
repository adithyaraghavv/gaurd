"""Git helpers: find a sensible base to diff against (repos do not always have `main`), and the files that
changed since a commit, for `guard scan --diff-since`.

Refs are validated and passed after `--`/as single arguments, never through a shell, so a hostile value cannot
become an option or a command."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

SAFE_REF = re.compile(r"^[A-Za-z0-9._/@^~{}\-]+$")
CANDIDATES = ("main", "master", "origin/main", "origin/master", "trunk", "develop")


class GitError(Exception):
    pass


def _git(args: list[str], cwd: str = ".") -> str:
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, timeout=60, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GitError(f"git failed: {e}") from e
    if p.returncode != 0:
        raise GitError(p.stderr.strip() or "git returned an error")
    return p.stdout


def in_repo(cwd: str = ".") -> bool:
    try:
        return _git(["rev-parse", "--is-inside-work-tree"], cwd).strip() == "true"
    except GitError:
        return False


def _ok(ref: str, cwd: str) -> bool:
    try:
        _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd)
        return True
    except GitError:
        return False


def base_ref(cwd: str = ".") -> tuple[str, str]:
    """(ref to diff against, how it was chosen). Works when the repo has no `main`:
    the remote's default branch, then common names, then the upstream, then the first commit."""
    if not in_repo(cwd):
        raise GitError("not inside a git repository")
    head = _git(["rev-parse", "HEAD"], cwd).strip()
    tries: list[tuple[str, str]] = []
    try:  # the remote's default branch, whatever it is called
        sym = _git(["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], cwd).strip()
        tries.append((sym.removeprefix("refs/remotes/"), "the remote's default branch"))
    except GitError:
        pass
    tries += [(c, f"branch '{c}'") for c in CANDIDATES]
    tries.append(("@{upstream}", "this branch's upstream"))
    for ref, why in tries:
        if not _ok(ref, cwd):
            continue
        try:
            mb = _git(["merge-base", "HEAD", ref], cwd).strip()
        except GitError:
            continue
        if mb != head:  # a real fork point: everything on this branch since it split off
            return mb, why
        # We ARE on that branch, so the base is simply the previous commit.
        if _ok("HEAD~1", cwd):
            return "HEAD~1", f"{why} (you are on it, so the last commit)"
    roots = _git(["rev-list", "--max-parents=0", "HEAD"], cwd).split()
    if roots and roots[-1] != head:
        return roots[-1], "the first commit (no default branch found)"
    return "HEAD", "no earlier commit to compare with; only uncommitted changes count"


def changed_files(since: str, cwd: str = ".") -> set[Path]:
    """Files changed since `since` (a commit or `auto`), including uncommitted and new files."""
    if since == "auto":
        since = base_ref(cwd)[0]
    if not SAFE_REF.match(since) or since.startswith("-"):
        raise GitError(f"not a valid commit reference: {since!r}")
    if not _ok(since, cwd):
        raise GitError(f"unknown commit: {since!r}")
    root = Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())
    names = _git(["diff", "--name-only", "--diff-filter=ACMR", since, "--"], cwd).splitlines()
    names += _git(["ls-files", "--others", "--exclude-standard"], cwd).splitlines()
    return {(root / n).resolve() for n in names if n}
