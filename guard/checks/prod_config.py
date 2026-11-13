"""Production configuration lint. Reads files only: it never connects to anything, production or otherwise.

It looks for things that must not ship:
- in production env files (named .env.production / .env.prod, or setting APP_ENV, NODE_ENV... to production):
  debug mode, demo or auth-bypass switches, wildcard CORS, default or short secrets, plain http or localhost URLs,
  database URLs with sslmode=disable;
- in settings code: wildcard CORS, debug=True, default secrets, demo logins that default to on;
- in deploy config (netlify.toml, vercel.json, _headers): missing security headers;
- across the project (heuristic): login-style routes with no rate limiting anywhere, and a backend with no
  security-header middleware.

Findings name the variable and its length, never its value: a report that quotes a secret is a leak of its own."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from ..coverage import Skipped
from .. import files as filesmod
from ..files import walk
from ..findings import Finding

SUFFIXES = (".env", ".production", ".prod", ".staging", ".local", ".example", ".development", ".py", ".js", ".ts",
            ".tsx", ".mjs", ".toml", ".yml", ".yaml", ".conf", ".json", "_headers", "Dockerfile", "Procfile", "Caddyfile")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures|e2e|examples?)(/|$)|\.(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$", re.I)
ENV_NAME = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.env)$")
ENV_KINDS = {"APP_ENV", "ENV", "NODE_ENV", "ENVIRONMENT", "FLASK_ENV", "RAILS_ENV", "DJANGO_ENV", "PYTHON_ENV"}
LOCAL = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
TRUTHY = {"1", "true", "yes", "on", "y"}
ACCEPT = "If this is intended, record it under accepted_risks in guard.config.json with a reason and an owner."

DEBUG_KEY = re.compile(r"(^|_)DEBUG$", re.I)
BYPASS_KEY = re.compile(r"DEMO|BYPASS|SKIP_AUTH|DISABLE_AUTH|AUTH_DISABLED|NO_AUTH|TEST_LOGIN|DEV_LOGIN|MOCK_AUTH|INSECURE", re.I)
CORS_KEY = re.compile(r"CORS|ALLOWED?_ORIGINS?", re.I)
SECRET_KEY = re.compile(r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|JWT|SIGNING|ENCRYPTION", re.I)
NOT_SECRET = re.compile(r"PUBLIC|PUBLISHABLE|ANON|_URL$|_URI$|_ID$|_NAME$|_TTL|_DAYS|_ENABLED$|_PROVIDER$|_SECONDS$|_MINUTES$|_VERSION$|_LANG$|_TEMPLATE$|_BASE$|_FIELD$", re.I)
STRONG_KEY = re.compile(r"SECRET|JWT|PRIVATE|SIGNING|ENCRYPTION", re.I)
PLACEHOLDER = re.compile(r"^(change[-_ ]?me|secret|password|passwd|admin|test|testing|example|dev|default|xxx+|todo|dummy|sample|"
                         r"your[-_ ]|replace|placeholder|insert|none|null|abc|123)|dev[-_]only|change[-_]?me|yourapp|example\.", re.I)
URL_KEY = re.compile(r"(_URL|_URI|_ORIGIN|_HOST|_ENDPOINT)$", re.I)


def is_test(path: str) -> bool:
    return bool(TEST_PATH.search(path.replace("\\", "/")))


def parse_env(text: str) -> list[tuple[int, str, str]]:
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[7:]
        k, v = line.split("=", 1)
        v = v.strip()
        if v and v[0] in "\"'" and v.count(v[0]) >= 2:
            v = v[1:v.index(v[0], 1)]
        else:
            v = re.split(r"\s+#", v, 1)[0].strip()
        out.append((n, k.strip(), v))
    return out


def is_prod_env(path: str, pairs: list[tuple[int, str, str]]) -> bool:
    name = Path(path).name.lower()
    if re.search(r"prod", name):
        return True
    return any(k.upper() in ENV_KINDS and v.strip().lower() in ("prod", "production") for _, k, v in pairs)


def _f(sev, title, detail, path, line=0, fix="", tags=()):
    return Finding("prod_config", sev, title, detail, f"{path}:{line}" if line else path, fix=(fix + " " + ACCEPT).strip(),
                   tags=["config", *tags])


def evaluate_env(path: str, text: str) -> list[Finding]:
    pairs = parse_env(text)
    if not is_prod_env(path, pairs):
        return []
    out: list[Finding] = []
    for n, k, v in pairs:
        low = v.strip().lower()
        if DEBUG_KEY.search(k) and low in TRUTHY:
            out.append(_f("high", f"Debug mode is on in production config ({k})", "Debug mode shows stack traces and "
                          "internals to anyone, and often disables protections.", path, n, "Set it to false."))
        if BYPASS_KEY.search(k) and low in TRUTHY:
            out.append(_f("high", f"Demo or auth-bypass switch is on in production config ({k})",
                          "A demo login or auth bypass left on lets anyone in.", path, n, "Turn it off in production."))
        if CORS_KEY.search(k) and "*" in v:
            out.append(_f("high", f"Wildcard CORS in production config ({k})", "Any website may call the API from a "
                          "visitor's browser.", path, n, "List the exact origins you serve."))
        if SECRET_KEY.search(k) and not NOT_SECRET.search(k) and v:
            if PLACEHOLDER.search(v):
                out.append(_f("high", f"Default or placeholder secret in production config ({k})",
                              f"{k} (length {len(v)}) looks like a placeholder, not a real secret.", path, n,
                              "Generate a long random value and keep it in the host's secret store.", ["secrets"]))
            elif STRONG_KEY.search(k) and len(v) < 16:
                out.append(_f("medium", f"Short secret in production config ({k})", f"{k} is only {len(v)} characters.",
                              path, n, "Use at least 32 random characters.", ["secrets"]))
        if URL_KEY.search(k) or "://" in v:
            try:
                u = urlparse(v)
            except ValueError:
                continue
            host = (u.hostname or "").lower()
            if host in LOCAL:
                out.append(_f("medium", f"Production config points at localhost ({k})", "A production value that "
                              "points at the machine itself is almost always a leftover from development.", path, n,
                              "Use the real service address."))
            elif u.scheme == "http" and host:
                out.append(_f("medium", f"Plain http URL in production config ({k})", "Traffic to it is not "
                              "encrypted.", path, n, "Use https."))
            if re.search(r"sslmode=disable", v, re.I):
                out.append(_f("high", f"Database connection without TLS in production config ({k})",
                              "sslmode=disable sends database traffic unencrypted.", path, n, "Use sslmode=require."))
    return out


WILD_ORIGINS = re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,=]\s*["']\*["']|
                              \borigin\s*:\s*["']\*["']|\bcors\s*\(\s*\)""", re.I | re.X)
CREDS = re.compile(r"allow_credentials\s*=\s*True|credentials\s*:\s*true", re.I)
DEBUG_CODE = re.compile(r"\bdebug\s*=\s*True\b|\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b", re.I | re.M)
DEFAULT_SECRET = re.compile(r"""\b([A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|API_?KEY|PRIVATE_?KEY|SIGNING)[A-Z0-9_]*)\s*(?::\s*\w+\s*)?=\s*["']([^"']{3,})["']""")
DEMO_ON = re.compile(r"\b(demo[_-]?login[_-]?enabled|enable[_-]?demo\w*|auth[_-]?bypass\w*)\s*(?::\s*\w+\s*)?[:=]\s*(True|true)\b")
SETTINGS_FILE = re.compile(r"(settings|config|conf|constants)[^/]*\.(py|js|ts)$", re.I)


def evaluate_code(path: str, text: str) -> list[Finding]:
    if is_test(path):
        return []
    out: list[Finding] = []
    m = WILD_ORIGINS.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        sev = "high" if CREDS.search(text) else "medium"
        out.append(_f(sev, "Wildcard CORS in code", "Every website may call this API from a visitor's browser" +
                      (", and credentials are allowed too." if sev == "high" else "."), path, line,
                      "List the exact origins you serve (read them from an environment variable)."))
    m = DEBUG_CODE.search(text)
    if m and (SETTINGS_FILE.search(path) or "app.run" in m.group(0) or "FastAPI" in text or "Flask" in text):
        out.append(_f("medium", "Debug mode switched on in code", "Debug mode shows internals and often disables "
                      "protections.", path, text.count("\n", 0, m.start()) + 1, "Read it from the environment and default to false."))
    for m in DEFAULT_SECRET.finditer(text):
        name, val = m.group(1), m.group(2)
        if PLACEHOLDER.search(val) and not NOT_SECRET.search(name):
            out.append(_f("medium", f"Default secret in code ({name})", f"{name} has a placeholder value in source "
                          f"(length {len(val)}). Fine only if production refuses to start with it.", path,
                          text.count("\n", 0, m.start()) + 1, "Make the app fail to start in production unless the real "
                          "secret is set.", ["secrets"]))
    m = DEMO_ON.search(text)
    if m:
        out.append(_f("low", f"Demo or bypass login defaults to on ({m.group(1)})", "Make sure production turns it off "
                      "(and that the app refuses to start otherwise).", path, text.count("\n", 0, m.start()) + 1,
                      "Default it to false, or tie it to a non-production environment check."))
    return out


HEADERS = {
    "strict-transport-security": ("medium", "Strict-Transport-Security"),
    "x-content-type-options": ("low", "X-Content-Type-Options"),
    "content-security-policy": ("medium", "Content-Security-Policy"),
    "referrer-policy": ("low", "Referrer-Policy"),
}


def evaluate_deploy(path: str, text: str) -> list[Finding]:
    """Security headers in a static host's config (netlify.toml, vercel.json, _headers)."""
    name = Path(path).name.lower()
    if name not in ("netlify.toml", "vercel.json", "_headers", "firebase.json"):
        return []
    low = text.lower()
    return [_f(sev, f"{label} is not configured in {name}", f"The deploy config sets no {label} header, so the "
               "hosted site will not send it.", path, 0, f"Add a headers rule that sets {label}.")
            for key, (sev, label) in HEADERS.items() if key not in low]


AUTH_ROUTE = re.compile(r"""["'`]/?(?:api/)?(?:auth/)?(login|signin|sign-in|token|register|signup|sign-up|password|forgot|reset)[\w/\-]*["'`]""", re.I)
ROUTE_CALL = re.compile(r"(@\w+\.(post|get|put|route)|\.(post|get|put|route|use)\s*\(|path\s*\(|router\.)", re.I)
RATE_HINT = re.compile(r"rate[-_ ]?limit|slowapi|throttl|limiter|limit_req|express-rate-limit|ratelimit", re.I)
SEC_HEADER_HINT = re.compile(r"helmet|SecurityMiddleware|secure_headers|SecureHeaders|X-Content-Type-Options|"
                             r"Strict-Transport-Security|Content-Security-Policy|secure\.Secure", re.I)
BACKEND = re.compile(r"\bfastapi\b|\bflask\b|\bdjango\b|\bexpress\b|\bkoa\b|\bfastify\b", re.I)


def project_findings(files: list[tuple[str, str]], deploy_paths: list[str]) -> list[Finding]:
    """Cross-file heuristics. `files` are the non-test source/config files as (path, text)."""
    out: list[Finding] = []
    code = [(p, t) for p, t in files if p.endswith((".py", ".js", ".ts", ".tsx", ".mjs"))]
    routes = []
    for p, t in code:
        for n, line in enumerate(t.splitlines(), 1):
            if AUTH_ROUTE.search(line) and ROUTE_CALL.search(line):
                routes.append((p, n))
                break
    hay = [t for _, t in files]
    if routes and not any(RATE_HINT.search(t) for t in hay):
        p, n = routes[0]
        out.append(_f("medium", "Login-style routes found but no rate limiting anywhere",
                      f"{len(routes)} file(s) define login, token, register or password routes and nothing in the code, "
                      "dependencies or deploy config mentions rate limiting. Heuristic: a proxy or the identity "
                      "provider may be doing it.", p, n, "Add per-IP and per-account limits on these routes."))
    names = " ".join(Path(p).name.lower() for p in [p for p, _ in files])
    is_backend = any(BACKEND.search(t) for p, t in files if Path(p).name.lower() in
                     ("requirements.txt", "pyproject.toml", "package.json") or p.endswith(".py"))
    if is_backend and not any(SEC_HEADER_HINT.search(t) for t in hay) and not deploy_paths:
        out.append(_f("low", "No security-header handling found for the backend",
                      "A web backend was detected but no code or config mentions security headers (helmet, "
                      "Strict-Transport-Security, Content-Security-Policy...). Heuristic: a proxy may add them.",
                      code[0][0] if code else ".", 0, "Add a security-headers middleware or set them at the proxy."))
    return out


def run(cfg, http) -> list[Finding]:
    findings: list[Finding] = []
    files: list[tuple[str, str]] = []
    deploy: list[str] = []
    seen = 0
    for p in walk(cfg.source_dir, SUFFIXES, all_files=True):
        sp = str(p)
        if is_test(sp) or "package-lock" in p.name or p.name.endswith((".lock", ".min.js")):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        seen += 1
        changed = filesmod.is_changed(p)
        if ENV_NAME.search(sp.replace("\\", "/")):
            if changed:
                findings += evaluate_env(sp, text)
            continue
        if p.name.lower() in ("netlify.toml", "vercel.json", "_headers", "firebase.json"):
            deploy.append(sp)
            if changed:
                findings += evaluate_deploy(sp, text)
        files.append((sp, text))
        if changed and p.suffix in (".py", ".js", ".ts", ".tsx", ".mjs"):
            findings += evaluate_code(sp, text)
    if not seen:
        raise Skipped("no config or source files found under source_dir", applicable=False)
    if filesmod.CHANGED is None:
        findings += project_findings(files, deploy)
    else:
        findings.append(Finding("prod_config", "info", "project-wide heuristics (rate limits, security headers) skipped in "
                                "--diff-since mode", "", tags=["coverage-note"]))
    return findings
