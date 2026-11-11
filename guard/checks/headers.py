"""Security response headers.

Reported once per host and header (not once per path), and only where the header means something:
- Content-Security-Policy and framing protection protect HTML pages, so they are only expected on HTML responses,
  not on JSON API replies.
- Strict-Transport-Security only works over HTTPS, so it is not expected on plain-http local addresses."""
from __future__ import annotations

from urllib.parse import urlparse

from ..findings import Finding

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
# header -> (severity, fix, only_on_html)
REQUIRED = {
    "strict-transport-security": ("medium", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", False),
    "x-content-type-options": ("low", "Add 'X-Content-Type-Options: nosniff'.", False),
    "content-security-policy": ("medium", "Add a restrictive Content-Security-Policy.", True),
    "referrer-policy": ("low", "Add 'Referrer-Policy: strict-origin-when-cross-origin'.", False),
}
LEAKY = ("server", "x-powered-by")


def is_html(headers: dict) -> bool:
    """HTML when the content type says so. A response with no content type is treated as HTML (the cautious
    reading), so the checks are not silently skipped."""
    ct = headers.get("content-type")
    return ct is None or "html" in ct.lower()


def _local_plain_http(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "http" and (u.hostname or "").lower() in LOCAL_HOSTS


def evaluate(url: str, headers: dict, html: bool | None = None) -> list[Finding]:
    html = is_html(headers) if html is None else html
    out: list[Finding] = []
    for name, (sev, fix, html_only) in REQUIRED.items():
        if name in headers or (html_only and not html):
            continue
        if name == "strict-transport-security" and _local_plain_http(url):
            continue
        out.append(Finding("headers", sev, f"Missing {name}", f"{url} does not send {name}.", url, fix=fix))
    if html and "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        out.append(Finding("headers", "low", "No clickjacking protection", f"{url} can be framed.", url,
                           fix="Add 'X-Frame-Options: DENY' or CSP frame-ancestors."))
    for name in LEAKY:
        val = headers.get(name, "")
        if any(ch.isdigit() for ch in val):
            out.append(Finding("headers", "low", f"Version disclosure via {name}", f"{name}: {val}", url,
                               evidence=val, fix=f"Remove or genericize the {name} header."))
    return out


def run(cfg, http) -> list[Finding]:
    base = cfg.base_url.rstrip("/")
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base))
    merged: dict[str, Finding] = {}
    paths_for: dict[str, list[str]] = {}
    for path in cfg.probe_slice():
        status, hdrs, _ = http.request("GET", base + path)
        if status == 0:
            continue
        for f in evaluate(origin, hdrs):  # judged per response, reported per host
            merged.setdefault(f.title, f)
            paths_for.setdefault(f.title, []).append(path)
    for title, f in merged.items():
        shown = paths_for[title]
        f.evidence = f"seen on {len(shown)} path(s): " + ", ".join(shown[:6]) + (" ..." if len(shown) > 6 else "")
    return list(merged.values())
