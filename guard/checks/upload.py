"""File upload check. Uploads harmless files with risky types/names to your own
staging upload endpoint and flags the ones the server accepts."""
from __future__ import annotations

from ..coverage import Skipped
from ..findings import Finding

BOUNDARY = "----guardkit"
TESTS = [
    ("guard.php", "application/x-php", b"<?php echo 1; ?>", "high"),
    ("guard.jpg.php", "image/jpeg", b"<?php echo 1; ?>", "high"),
    ("guard.html", "text/html", b"<script>1</script>", "medium"),
    ("guard.svg", "image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>", "medium"),
    ("guard.exe", "application/octet-stream", b"MZ-guard-test", "medium"),
]


def build_multipart(field: str, filename: str, ctype: str, content: bytes) -> tuple[bytes, str]:
    head = (f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n').encode()
    return head + content + f"\r\n--{BOUNDARY}--\r\n".encode(), f"multipart/form-data; boundary={BOUNDARY}"


def evaluate(url: str, filename: str, status: int, severity: str) -> list[Finding]:
    if status in range(200, 300):
        return [Finding("upload", severity, f"Dangerous file type accepted: {filename}",
                        "The upload endpoint stored a risky file type.", url, evidence=f"status={status}",
                        fix="Allowlist extensions AND verify content type/magic bytes; store outside the web root "
                            "or on object storage; serve with Content-Disposition: attachment.",
                        tags=["owasp-a04"])]
    return []


def run(cfg, http) -> list[Finding]:
    if not cfg.upload_path:
        raise Skipped("no upload_path configured")
    headers = cfg.auth_headers("upload")
    if headers is None:
        raise Skipped(f"token '{cfg.check_tokens.get('upload')}' (check_tokens.upload) is not set")
    url = cfg.base_url.rstrip("/") + cfg.upload_path
    findings: list[Finding] = []
    for name, ctype, content, sev in TESTS:
        body, content_type = build_multipart(cfg.upload_field, name, ctype, content)
        status, _, _ = http.request("POST", url, {**headers, "Content-Type": content_type}, body)
        findings += evaluate(url, name, status, sev)
    return findings
