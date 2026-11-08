import json
import unittest

from guard.checks import cors, headers, injection, ratelimit, tenant
from guard.findings import Finding
from guard.report import exceeds, to_markdown, to_sarif
from guard.runners import parse_gitleaks, parse_semgrep, parse_trivy
from guard.scope import Scope, ScopeError


class ScopeTests(unittest.TestCase):
    def test_blocks_unlisted_host(self):
        with self.assertRaises(ScopeError):
            Scope(["staging.a.com"]).check("https://other.com/x")

    def test_allows_listed_staging(self):
        Scope(["staging.a.com"]).check("https://staging.a.com/x")

    def test_blocks_prod_looking_host(self):
        with self.assertRaises(ScopeError):
            Scope(["www.a.com"]).check("https://www.a.com/")

    def test_prod_opt_in(self):
        Scope(["www.a.com"], allow_production=True).check("https://www.a.com/")

    def test_localhost_ok(self):
        Scope(["localhost"]).check("http://localhost:8000/")


class CheckTests(unittest.TestCase):
    def test_headers_missing(self):
        titles = [f.title for f in headers.evaluate("u", {})]
        self.assertIn("Missing strict-transport-security", titles)

    def test_headers_clean(self):
        h = {"strict-transport-security": "x", "x-content-type-options": "nosniff",
             "content-security-policy": "frame-ancestors 'none'", "referrer-policy": "no-referrer"}
        self.assertEqual(headers.evaluate("u", h), [])

    def test_cors_reflect_with_creds(self):
        f = cors.evaluate("u", {"access-control-allow-origin": cors.EVIL_ORIGIN,
                                "access-control-allow-credentials": "true"})
        self.assertEqual(f[0].severity, "high")

    def test_tenant_idor_detected(self):
        f = tenant.evaluate("u", 200, 401, 200, "secret")
        self.assertEqual(f[0].severity, "critical")

    def test_tenant_isolated(self):
        self.assertEqual(tenant.evaluate("u", 200, 401, 403, ""), [])

    def test_tenant_anon_open(self):
        self.assertEqual(tenant.evaluate("u", 200, 200, 403, "")[0].severity, "critical")

    def test_injection_error_based(self):
        f = injection.evaluate("u", "q", "ok", "syntax error at or near \"'\"", "", "")
        self.assertEqual(f[0].severity, "high")

    def test_injection_clean(self):
        self.assertEqual(injection.evaluate("u", "q", "ok", "ok", "ok", "ok"), [])

    def test_ratelimit_missing(self):
        self.assertEqual(ratelimit.evaluate("u", [401] * 30)[0].severity, "medium")

    def test_ratelimit_present(self):
        self.assertEqual(ratelimit.evaluate("u", [401] * 10 + [429] * 20), [])


class ParserAndReportTests(unittest.TestCase):
    def test_semgrep(self):
        raw = json.dumps({"results": [{"check_id": "r", "path": "a.py", "start": {"line": 3},
                                       "extra": {"severity": "ERROR", "message": "m"}}]})
        self.assertEqual(parse_semgrep(raw)[0].severity, "high")

    def test_gitleaks(self):
        raw = json.dumps([{"RuleID": "aws", "File": "x", "StartLine": 1}])
        self.assertEqual(parse_gitleaks(raw)[0].tags, ["secrets"])

    def test_trivy(self):
        raw = json.dumps({"Results": [{"Target": "req.txt", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "CRITICAL", "FixedVersion": "2"}]}]})
        self.assertEqual(parse_trivy(raw)[0].severity, "critical")

    def test_exceeds_and_formats(self):
        fs = [Finding("c", "high", "t", "d")]
        self.assertTrue(exceeds(fs, "high"))
        self.assertFalse(exceeds(fs, "critical"))
        self.assertIn("[HIGH] t", to_markdown(fs, []))
        self.assertEqual(json.loads(to_sarif(fs))["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
