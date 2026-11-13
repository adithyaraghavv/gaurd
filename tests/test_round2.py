"""Round 2: partial scans, pinned installer, first-run setup, Supabase audit, production lint, route-level tenant
tests, launch readiness, diff mode."""
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from datetime import date, timedelta
from pathlib import Path

from guard import cli, dryrun, explain, files as filesmod, gitdiff, openapi, readiness, scanners
from guard.checks import ALL_CHECKS, OFFLINE_OK, prod_config, supabase_audit, tenant_routes
from guard.config import DEFAULT_CONFIG, Config
from guard.coverage import Coverage, Skipped, percent, required_missing, result_line
from guard.findings import Finding
from guard.loop import record_run, write_fix_tasks, write_summary
from guard.scope import Scope, ScopeError

SCANNERS = cli.SCANNER_NAMES


def titles(fs):
    return [f.title for f in fs]


def sev(fs):
    return [f.severity for f in fs]


class FakeHTTP:
    def __init__(self, responder):
        self.responder, self.calls, self.last_set_cookies = responder, [], []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.responder(method, url, headers or {}, body)


def run_cli(argv, files=None, cfg=None, env=None):
    """Run guard in a scratch directory. Returns (exit code, stdout, stderr, directory contents reader)."""
    with tempfile.TemporaryDirectory() as d:
        old = os.getcwd()
        os.chdir(d)
        saved = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        try:
            for name, text in (files or {}).items():
                Path(name).parent.mkdir(parents=True, exist_ok=True)
                Path(name).write_text(text)
            if cfg is not None:
                Path("guard.config.json").write_text(json.dumps(cfg))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
            read = {p.name: p.read_text() for p in Path(d).rglob("*") if p.is_file() and ".git/" not in str(p)}
            return code, out.getvalue(), err.getvalue(), read
        finally:
            os.chdir(old)
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class PatchedScanners(unittest.TestCase):
    """Makes the outside scanners deterministic: present or missing, whatever the machine has."""
    missing = True

    def setUp(self):
        self._orig = cli.scan_tools
        miss = self.missing
        cli.scan_tools = lambda src: ([], [
            Coverage(f"{t} ({w})", "skipped" if miss else "ran", "not installed" if miss else "")
            for t, w in (("semgrep", "code scan"), ("gitleaks", "secret scan"), ("trivy", "dependency scan"))])

    def tearDown(self):
        cli.scan_tools = self._orig


# ---- 1. a partial scan cannot be mistaken for a pass ----------------------------------------------------------------
class ResultLineTests(unittest.TestCase):
    COV = [Coverage("semgrep (code scan)", "skipped", "x"), Coverage("gitleaks (secret scan)", "skipped", "x"),
           Coverage("trivy (dependency scan)", "skipped", "x"), Coverage("db_rules", "ran"), Coverage("db_access", "ran"),
           Coverage("prod_config", "ran")] + [Coverage(n, "off") for n in ("headers", "cors", "tenant")]

    def test_partial_line_says_partial_and_what_did_not_run(self):
        line = result_line(self.COV, SCANNERS, 0, 0)
        self.assertTrue(line.startswith("PARTIAL:"), line)
        self.assertIn("3 of 6 scanner checks did not run (semgrep, gitleaks, trivy)", line)
        self.assertIn("3 live checks off", line)
        self.assertIn("NOT a pass", line)
        self.assertNotIn("0 findings.", line)  # never the bare "0 findings"

    def test_complete_line(self):
        cov = [Coverage("db_rules", "ran"), Coverage("headers", "ran"), Coverage("jwt", "n/a")]
        self.assertTrue(result_line(cov, SCANNERS, 2, 0).startswith("COMPLETE:"))

    def test_blocking_findings_lead_the_line_and_partial_still_shows(self):
        line = result_line(self.COV, SCANNERS, 4, 2)
        self.assertTrue(line.startswith("FAIL: 2 blocking"), line)
        self.assertIn("PARTIAL:", line)

    def test_unconfigured_live_checks_are_counted_separately(self):
        cov = [Coverage("db_rules", "ran"), Coverage("tenant", "skipped", "not set"), Coverage("upload", "off")]
        line = result_line(cov, SCANNERS, 0, 0)
        self.assertIn("1 live checks off", line)
        self.assertIn("1 live checks skipped (not configured)", line)

    def test_percent(self):
        self.assertEqual(percent(self.COV), 33)  # 3 of 9
        self.assertIsNone(percent([Coverage("jwt", "n/a")]))
        self.assertEqual(percent([Coverage("a", "ran"), Coverage("b", "n/a")]), 100)

    def test_only_outside_scanners_are_required(self):
        cov = [Coverage("semgrep (code scan)", "skipped"), Coverage("tenant", "skipped"), Coverage("trivy (dependency scan)", "off")]
        self.assertEqual([c.name for c in required_missing(cov)], ["semgrep (code scan)"])

    def test_summary_shows_coverage_percentage_at_the_top(self):
        with tempfile.TemporaryDirectory() as d:
            res = record_run(d, [], "high", coverage=self.COV)
            text = write_summary(d, res, "high").read_text()
            self.assertIn("**Coverage:** 33% of applicable checks ran", text)
            self.assertLess(text.index("**Coverage:**"), text.index("| check |"))


class ExitCodeTests(PatchedScanners):
    def test_missing_required_scanners_exit_4_and_say_so(self):
        code, out, err, _ = run_cli(["scan", "--no-live"], cfg=DEFAULT_CONFIG)
        self.assertEqual(code, 4)
        self.assertTrue(out.startswith("PARTIAL:"), out)
        self.assertIn("--allow-partial", err)

    def test_allow_partial_overrides_but_the_report_still_says_partial(self):
        code, out, _, files = run_cli(["scan", "--no-live", "--allow-partial"], cfg=DEFAULT_CONFIG)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("PARTIAL:"))
        self.assertIn("NOT A FULL CLEAN", files["summary.md"])

    def test_blocking_findings_beat_allow_partial(self):
        sql = {"db/1.sql": "create table t (id int);"}
        code, out, _, _ = run_cli(["scan", "--no-live", "--allow-partial"], files=sql, cfg={**DEFAULT_CONFIG, "fail_on": "medium"})
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("FAIL:"), out)

    def test_choosing_not_to_run_scanners_is_not_a_partial_exit(self):
        code, out, _, _ = run_cli(["scan", "--no-live", "--only", "db_rules"], cfg=DEFAULT_CONFIG)
        self.assertEqual(code, 0)

    def test_dry_run_and_gate_are_unaffected(self):
        self.assertEqual(run_cli(["scan", "--dry-run"], cfg=DEFAULT_CONFIG)[0], 0)


class ExitCodeWithScannersPresent(PatchedScanners):
    missing = False

    def test_all_scanners_present_and_nothing_found_exits_0(self):
        code, out, _, _ = run_cli(["scan", "--no-live"], cfg=DEFAULT_CONFIG)
        self.assertEqual(code, 0)
        self.assertNotIn("scanner checks did not run", out)


class CrashIsolationTests(PatchedScanners):
    def test_a_crashing_check_is_reported_skipped_not_clean_and_does_not_stop_the_scan(self):
        original = ALL_CHECKS["db_rules"]

        def boom(cfg, http):
            raise RuntimeError("bug")
        ALL_CHECKS["db_rules"] = boom
        try:
            code, out, err, files = run_cli(["scan", "--no-live", "--only", "db_rules", "db_access"], cfg=DEFAULT_CONFIG)
        finally:
            ALL_CHECKS["db_rules"] = original
        self.assertIn("crashed", err)
        self.assertIn("| db_rules | SKIPPED | crashed: RuntimeError |", files["summary.md"])
        self.assertTrue(out.startswith("PARTIAL:"))


# ---- 2. pinned scanner installer ----------------------------------------------------------------------------------
def targz(name="gitleaks", payload=b"#!/bin/sh\necho gitleaks\n", member=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo(member or name)
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def lock_for(data, tool="gitleaks", url="https://example.test/gitleaks.tar.gz", sha=None, version="8.1.0", plat="linux-amd64"):
    return {"tools": {tool: {"version": version, "platforms": {plat: {
        "url": url, "sha256": sha or hashlib.sha256(data).hexdigest(), "binary": tool}}}}}


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "bin"
        self.lock = Path(self.tmp.name) / "scanners.lock"

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, lock, getter, **kw):
        self.lock.write_text(json.dumps(lock))
        return scanners.install(str(self.lock), dest=self.dest, getter=getter, plat="linux-amd64", **kw)

    def test_installs_a_download_that_matches_the_lock(self):
        data = targz()
        res = self.install(lock_for(data), lambda url: data)
        self.assertEqual(res[0][:2], ("gitleaks", "installed"))
        f = self.dest / "gitleaks"
        self.assertTrue(f.exists() and f.stat().st_mode & stat.S_IXUSR)
        self.assertIn(b"echo gitleaks", f.read_bytes())

    def test_checksum_mismatch_is_refused_and_nothing_is_written(self):
        data = targz()
        res = self.install(lock_for(data, sha="0" * 64), lambda url: data)
        self.assertEqual(res[0][1], "refused")
        self.assertIn("MISMATCH", res[0][2])
        self.assertFalse(self.dest.exists() and any(self.dest.iterdir()))

    def test_a_tampered_download_is_refused(self):
        good = targz()
        res = self.install(lock_for(good), lambda url: targz(payload=b"evil"))
        self.assertEqual(res[0][1], "refused")

    def test_placeholders_and_bad_entries_are_refused(self):
        data = targz()
        cases = [
            lock_for(data, sha="REPLACE_WITH_64_HEX_SHA256"),
            lock_for(data, version="REPLACE_WITH_VERSION"),
            lock_for(data, url="http://example.test/x.tar.gz"),
            lock_for(data, plat="darwin-arm64"),  # nothing for this platform: guard will not guess
        ]
        for lock in cases:
            self.assertEqual(self.install(lock, lambda url: data)[0][1], "refused", lock)

    def test_a_binary_name_with_a_path_is_refused(self):
        data = targz()
        lock = lock_for(data)
        lock["tools"]["gitleaks"]["platforms"]["linux-amd64"]["binary"] = "../evil"
        self.assertEqual(self.install(lock, lambda url: data)[0][1], "refused")

    def test_tools_not_in_the_lock_are_refused_not_picked_for_you(self):
        data = targz()
        res = self.install(lock_for(data), lambda url: data, only=["trivy"])
        self.assertEqual(res[0][:2], ("trivy", "refused"))
        self.assertIn("not in the lock", res[0][2])

    def test_only_known_tools_are_installable(self):
        data = targz()
        self.assertEqual(self.install(lock_for(data, tool="curl"), lambda url: data)[0][1], "refused")

    def test_semgrep_is_explained_not_installed(self):
        data = targz()
        res = self.install(lock_for(data, tool="semgrep"), lambda url: data)
        self.assertEqual(res[0][1], "skipped")
        self.assertIn("require-hashes", res[0][2])

    def test_missing_lock_file_explains_how_to_make_one(self):
        with self.assertRaises(scanners.LockError) as cm:
            scanners.install(str(Path(self.tmp.name) / "nope.lock"), dest=self.dest)
        self.assertIn("will not choose versions", str(cm.exception))

    def test_download_failure_installs_nothing(self):
        def fail(url):
            raise OSError("no network")
        res = self.install(lock_for(targz()), fail)
        self.assertEqual(res[0][1], "failed")

    def test_archive_member_with_a_path_cannot_write_outside_the_dest(self):
        data = targz(member="../../evil/gitleaks")
        res = self.install(lock_for(data), lambda url: data)
        self.assertEqual(res[0][1], "installed")
        self.assertEqual([p.name for p in self.dest.iterdir()], ["gitleaks"])  # only our fixed path was written
        self.assertFalse((Path(self.tmp.name).parent / "evil").exists())

    def test_zip_and_bare_binary(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("dist/gitleaks", b"zipbin")
        zdata = buf.getvalue()
        self.assertEqual(self.install(lock_for(zdata, url="https://e.test/g.zip"), lambda u: zdata)[0][1], "installed")
        self.assertEqual((self.dest / "gitleaks").read_bytes(), b"zipbin")
        raw = b"rawbin"
        self.assertEqual(self.install(lock_for(raw, url="https://e.test/gitleaks"), lambda u: raw)[0][1], "installed")

    def test_a_platform_entry_that_is_not_an_object_is_refused_clearly(self):
        data = targz()
        lock = lock_for(data)
        lock["tools"]["gitleaks"]["platforms"]["linux-amd64"] = "https://example.test/x"
        res = self.install(lock, lambda url: data)
        self.assertEqual(res[0][1], "refused")
        self.assertIn("must be an object", res[0][2])

    def test_an_oversized_archive_member_is_refused(self):
        old = scanners.MAX_BYTES
        scanners.MAX_BYTES = 10
        try:
            data = targz(payload=b"x" * 100)
            res = self.install(lock_for(data), lambda url: data)
        finally:
            scanners.MAX_BYTES = old
        self.assertEqual(res[0][1], "refused")
        self.assertIn("safety limit", res[0][2])

    def test_binary_missing_from_the_archive_is_refused(self):
        data = targz(name="other", member="other")
        self.assertEqual(self.install(lock_for(data), lambda url: data)[0][1], "refused")

    def test_cli_install_without_a_lock_exits_2_and_does_not_download(self):
        code, _, err, _ = run_cli(["doctor", "--install"], cfg=DEFAULT_CONFIG)
        self.assertEqual(code, 2)
        self.assertIn("scanners.lock", err)

    def test_installed_tools_are_found_by_the_scanner_runner(self):
        from guard import runners
        d = Path(self.tmp.name) / "bin2"
        d.mkdir()
        tool = d / "gitleaks"
        tool.write_text("#!/bin/sh\necho '[]'\n")
        tool.chmod(0o755)
        old = os.environ.get("GUARD_TOOLS_DIR")
        os.environ["GUARD_TOOLS_DIR"] = str(d)
        try:
            _, cov = runners.scan_tools(self.tmp.name)
        finally:
            os.environ.pop("GUARD_TOOLS_DIR") if old is None else os.environ.update(GUARD_TOOLS_DIR=old)
        status = {c.name.split(" ")[0]: c.status for c in cov}
        self.assertEqual(status["gitleaks"], "ran")


# ---- 3. first-run setup -------------------------------------------------------------------------------------------
class InitTests(unittest.TestCase):
    def test_init_with_a_url_writes_it_and_a_setup_guide(self):
        code, out, _, files = run_cli(["init", "--base-url", "https://staging.acme.dev/"])
        cfg = json.loads(files["guard.config.json"])
        self.assertEqual(code, 0)
        self.assertEqual((cfg["base_url"], cfg["allowed_hosts"]), ("https://staging.acme.dev", ["staging.acme.dev"]))
        self.assertFalse(cfg["setup_complete"])
        self.assertEqual((cfg["tenant_a_resources"], cfg["mass_assignment_targets"], cfg["rate_limit_path"]), ([], [], ""))  # no made-up routes
        self.assertIn("Two test tenants", files["GUARD_SETUP.md"])
        self.assertIn("TENANT_A_TOKEN", files["GUARD_SETUP.md"])
        self.assertIn("GUARD_SETUP.md", out)

    def test_init_refuses_production_looking_and_placeholder_hosts(self):
        for url in ("https://www.acme.com", "https://app.acme.com", "https://prod.acme.dev", "https://x.example", "ftp://s.acme.dev", "nonsense"):
            code, _, err, files = run_cli(["init", "--base-url", url])
            self.assertEqual(code, 2, url)
            self.assertNotIn("guard.config.json", files, url)

    def test_init_without_a_url_still_writes_placeholders_that_live_scans_refuse(self):
        code, out, _, files = run_cli(["init"])
        self.assertEqual(code, 0)
        self.assertIn("staging.yourapp.example", files["guard.config.json"])
        self.assertIn("setup_complete", out)

    def test_init_does_not_overwrite_an_existing_config(self):
        code, _, err, _ = run_cli(["init", "--base-url", "https://s.acme.dev"], cfg={"base_url": "keep"})
        self.assertEqual(code, 2)

    def test_the_setup_guide_never_contains_a_secret(self):
        import re
        self.assertIsNone(re.search(r"eyJ[\w-]{10,}\.[\w-]{10,}\.", cli.GUIDE))  # no real-looking token
        self.assertNotIn("Zq8vN2mXk4Rt7LpW9sYb3HcD6fGj1AeU", cli.GUIDE)


class ExplainTests(unittest.TestCase):
    def test_every_check_and_scanner_is_documented(self):
        for name in list(ALL_CHECKS) + ["semgrep", "gitleaks", "trivy"]:
            self.assertIn(name, explain.DOCS, f"no `guard doctor --explain {name}` text")
            text = explain.explain(name)
            self.assertIn("Needs:", text)
            self.assertIn("Writes data to your app:", text)

    def test_tenant_explanation_names_the_two_tokens(self):
        text = explain.explain("tenant")
        self.assertIn("tenant_a_token", text)
        self.assertIn("tenant_b_token", text)
        self.assertIn("DIFFERENT tenants", text)

    def test_write_checks_are_labelled(self):
        for name in ("mass_assignment", "upload", "ratelimit", "tenant_routes"):
            self.assertIn("YES", explain.explain(name), name)
        self.assertIn("no (read-only)", explain.explain("headers"))

    def test_unknown_check_lists_the_known_ones(self):
        self.assertIn("Known checks:", explain.explain("nope"))

    def test_cli_explain(self):
        code, out, _, _ = run_cli(["doctor", "--explain", "tenant"])
        self.assertEqual(code, 0)
        self.assertIn("Cross-tenant test", out)


class DryRunTests(PatchedScanners):
    CFG = {**DEFAULT_CONFIG, "setup_complete": True, "base_url": "https://staging.acme.dev",
           "allowed_hosts": ["staging.acme.dev"], "tenant_a_token": "A", "tenant_b_token": "B",
           "tenant_a_resources": ["/api/items/1"], "injection_params": ["q"], "probe_paths": ["/"],
           "rate_limit_path": "/api/login", "rate_limit_attempts": 3, "upload_path": "/api/up",
           "mass_assignment_targets": [{"path": "/api/profile", "method": "PATCH", "body": {"name": "x"}}]}

    def test_nothing_is_sent_and_every_request_is_listed(self):
        real = cli.ScopedHTTP
        cli.ScopedHTTP = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a real client was created"))
        try:
            code, out, _, files = run_cli(["scan", "--dry-run"], cfg=self.CFG)
        finally:
            cli.ScopedHTTP = real
        self.assertEqual(code, 0)
        self.assertIn("Nothing was sent", out)
        for needle in ("tenant:", "GET    https://staging.acme.dev/api/items/1", "ratelimit:", "mass_assignment:",
                       "upload:", "https://staging.acme.dev/api/profile"):
            self.assertIn(needle, out)
        self.assertIn("WRITE DATA", out)
        self.assertNotIn("guard_out", files)  # a dry run writes no report

    def test_a_dry_run_works_before_setup_is_complete_and_says_a_real_scan_would_be_refused(self):
        code, out, _, _ = run_cli(["scan", "--dry-run"], cfg={**self.CFG, "setup_complete": False})
        self.assertEqual(code, 0)
        self.assertIn("would be REFUSED right now", out)

    def test_hosts_the_scope_guard_would_refuse_are_marked(self):
        code, out, _, _ = run_cli(["scan", "--dry-run"], cfg={**self.CFG, "allowed_hosts": ["other.dev"]})
        self.assertIn("REFUSED", out)
        self.assertIn("would be REFUSED by the scope guard", out)

    def test_the_database_audit_is_listed_but_not_run(self):
        cfg = {**self.CFG, "db_audit_url": "postgresql://u:secretpw@db.stg.supabase.co:5432/postgres",
               "db_audit_allowed_hosts": ["db.stg.supabase.co"]}
        code, out, _, _ = run_cli(["scan", "--dry-run"], cfg=cfg)
        self.assertIn("read-only catalog queries", out)
        self.assertNotIn("secretpw", out)  # the password never appears

    def test_dry_run_plan_formatting_flags_writes(self):
        http = dryrun.DryRunHTTP(Scope(["s.dev"]))
        http.current = "upload"
        http.request("POST", "https://s.dev/up", {"Authorization": "Bearer x"}, b"abc")
        text = dryrun.format_plan(http.plan)
        self.assertIn("1 WRITE DATA", text)
        self.assertIn("auth: bearer token", text)


# ---- 4. Supabase / Postgres audit (read-only) ---------------------------------------------------------------------
class TomlAuditTests(unittest.TestCase):
    WEAK = """
[auth]
minimum_password_length = 6
password_requirements = ""
enable_anonymous_sign_ins = true
jwt_expiry = 604800 # a week
enable_refresh_token_rotation = false
additional_redirect_urls = ["https://*.acme.dev", "http://localhost:3000"]
[auth.email]
enable_confirmations = false
secure_password_change = false
double_confirm_changes = false
"""
    GOOD = """
[auth]
minimum_password_length = 12
password_requirements = "lower_upper_letters_digits"
enable_anonymous_sign_ins = false
jwt_expiry = 3600
enable_refresh_token_rotation = true
additional_redirect_urls = ["https://app.acme.dev"]
[auth.email]
enable_confirmations = true
secure_password_change = true
double_confirm_changes = true
"""

    def test_toml_parser(self):
        t = supabase_audit.parse_toml('[a.b]\nx = 1\ny = "s # not a comment" # comment\nz = true\n')
        self.assertEqual(t["a.b"], {"x": 1, "y": "s # not a comment", "z": True})

    def test_weak_settings_are_all_found(self):
        f = supabase_audit.config_findings("supabase/config.toml", self.WEAK)
        self.assertEqual(len(f), 9)
        self.assertIn("Minimum password length is 6", titles(f))
        self.assertIn("Email confirmation is off", titles(f))
        self.assertIn("Anonymous sign-ins are on", titles(f))
        self.assertIn("Wildcard redirect URL allowed", titles(f))
        self.assertEqual(next(x for x in f if "Access tokens" in x.title).severity, "medium")  # > a day
        self.assertTrue(all("dashboard" in x.detail for x in f))  # says hosted settings are separate

    def test_good_settings_are_clean(self):
        self.assertEqual(supabase_audit.config_findings("supabase/config.toml", self.GOOD), [])


class AdvisorImportTests(unittest.TestCase):
    LINTS = [
        {"name": "auth_leaked_password_protection", "title": "Leaked Password Protection Disabled", "level": "WARN",
         "facing": "EXTERNAL", "description": "Leaked password protection is currently disabled.",
         "remediation": "https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection",
         "metadata": {}},
        {"name": "rls_disabled_in_public", "title": "RLS Disabled in Public", "level": "ERROR",
         "metadata": {"schema": "public", "name": "notes", "type": "table"}, "description": "no rls"},
        {"name": "x", "title": "Info thing", "level": "INFO"},
    ]

    def test_levels_map_to_severities_and_remediation_is_kept(self):
        f = supabase_audit.advisor_findings("a.json", json.dumps(self.LINTS))
        self.assertEqual(sev(f), ["medium", "high", "low"])
        self.assertIn("(public.notes)", f[1].title)
        self.assertIn("password-security", f[0].fix)
        self.assertIn("auth_leaked_password_protection", f[0].tags)

    def test_wrapped_shapes_are_accepted(self):
        for wrapped in ({"lints": self.LINTS}, {"result": self.LINTS}, {"data": {"lints": self.LINTS}}):
            self.assertEqual(len(supabase_audit.advisor_findings("a.json", json.dumps(wrapped))), 3)

    def test_unknown_shape_gives_nothing_and_bad_json_raises(self):
        self.assertEqual(supabase_audit.advisor_findings("a.json", '{"hello": 1}'), [])
        with self.assertRaises(ValueError):
            supabase_audit.advisor_findings("a.json", "not json")


class ReadOnlyGuaranteeTests(unittest.TestCase):
    def test_only_a_single_select_is_ever_accepted(self):
        for ok in ("select 1", "  SELECT x from t;", "select * from pg_policies"):
            supabase_audit.assert_read_only(ok)
        for bad in ("insert into t values (1)", "update t set a=1", "delete from t", "drop table t", "create table t()",
                    "select 1; drop table t", "with x as (delete from t returning *) select * from x", "alter role x",
                    "grant all on t to x", "copy t to program 'x'"):
            with self.assertRaises(ValueError, msg=bad):
                supabase_audit.assert_read_only(bad)

    def test_every_built_in_query_passes_the_guard(self):
        for name, sql in supabase_audit.QUERIES.items():
            supabase_audit.assert_read_only(sql)

    def test_psql_runs_inside_a_read_only_transaction_and_hides_the_password(self):
        seen = {}

        class P:
            returncode, stdout = 0, "a,b\n1,2\n"

        def fake_run(cmd, **kw):
            seen.update(cmd=cmd, **kw)
            return P()
        rows = supabase_audit.psql_rows("postgresql://reader:s3cr%40t@db.stg.co:6543/app?sslmode=require",
                                        "select 1 as a, 2 as b", run=fake_run)
        self.assertEqual(rows, [{"a": "1", "b": "2"}])
        self.assertTrue(seen["input"].startswith("BEGIN READ ONLY;"))
        self.assertIn("ROLLBACK", seen["input"])
        self.assertNotIn("s3cr", " ".join(seen["cmd"]))  # not in the process list
        self.assertEqual(seen["env"]["PGPASSWORD"], "s3cr@t")
        self.assertEqual((seen["env"]["PGHOST"], seen["env"]["PGPORT"], seen["env"]["PGUSER"]), ("db.stg.co", "6543", "reader"))
        self.assertEqual(seen["env"]["PGSSLMODE"], "require")

    def test_psql_failure_does_not_leak_the_url(self):
        class P:
            returncode, stdout, stderr = 2, "", "FATAL: password authentication failed for user reader"

        with self.assertRaises(RuntimeError) as cm:
            supabase_audit.psql_rows("postgresql://reader:pw@h/db", "select 1", run=lambda *a, **k: P())
        self.assertNotIn("pw", str(cm.exception))
        self.assertNotIn("reader", str(cm.exception))

    def test_timeouts_and_a_missing_psql_are_clean_errors(self):
        for exc in (subprocess.TimeoutExpired("psql", 60), FileNotFoundError("psql")):
            def boom(*a, **k):
                raise exc
            with self.assertRaises(RuntimeError) as cm:
                supabase_audit.psql_rows("postgresql://u:pw@h/db", "select 1", run=boom)
            self.assertNotIn("pw", str(cm.exception))

    def test_remote_hosts_default_to_requiring_tls(self):
        seen = {}

        class P:
            returncode, stdout = 0, ""
        supabase_audit.psql_rows("postgresql://u@db.remote.co/x", "select 1", run=lambda c, **k: seen.update(k) or P())
        self.assertEqual(seen["env"]["PGSSLMODE"], "require")


class LiveScopeTests(unittest.TestCase):
    def cfg(self, url, hosts, **kw):
        return Config(db_audit_url=url, db_audit_allowed_hosts=hosts, **kw)

    def test_listed_staging_host_is_allowed(self):
        self.assertEqual(supabase_audit.check_target(self.cfg("postgresql://u@db.stg.co/x", ["db.stg.co"])), "db.stg.co")

    def test_unlisted_host_is_refused(self):
        with self.assertRaises(ScopeError) as cm:
            supabase_audit.check_target(self.cfg("postgresql://u@db.other.co/x", ["db.stg.co"]))
        self.assertIn("db_audit_allowed_hosts", str(cm.exception))

    def test_production_looking_host_is_refused_even_if_listed(self):
        for host in ("prod.db.co", "production-db.co", "www.db.co", "app.db.co"):
            with self.assertRaises(ScopeError, msg=host):
                supabase_audit.check_target(self.cfg(f"postgresql://u@{host}/x", [host]))

    def test_no_allowlist_means_no_connection(self):
        with self.assertRaises(ScopeError):
            supabase_audit.check_target(self.cfg("postgresql://u@db.stg.co/x", []))

    def test_localhost_is_fine(self):
        supabase_audit.check_target(self.cfg("postgresql://u@localhost/x", ["localhost"]))


def rows_for(**over):
    base = {
        "tables": [{"relname": "notes", "relrowsecurity": "t"}],
        "policies": [], "grants": [], "functions": [], "views": [],
        "has_storage": [{"present": "f"}], "buckets": [],
    }
    base.update(over)
    return lambda name: base[name]


class LiveCatalogTests(unittest.TestCase):
    def test_a_clean_database_has_no_findings(self):
        f = supabase_audit.live_findings("db.stg.co", rows_for(
            policies=[{"schemaname": "public", "tablename": "notes", "policyname": "own", "cmd": "ALL",
                       "roles": "authenticated", "qual": "(owner_id = auth.uid())", "with_check": "(owner_id = auth.uid())"}],
            grants=[{"table_name": "notes", "grantee": "authenticated", "privilege_type": "SELECT"}],
            functions=[{"proname": "f", "prosecdef": "t", "config": "search_path=\"\"", "returns": "int", "anon_exec": "f"}],
            views=[{"relname": "v", "options": "security_invoker=true"}]))
        self.assertEqual(f, [])

    def test_every_kind_of_problem_is_found(self):
        f = supabase_audit.live_findings("db.stg.co", rows_for(
            tables=[{"relname": "notes", "relrowsecurity": "t"}, {"relname": "open", "relrowsecurity": "f"}],
            policies=[{"schemaname": "public", "tablename": "notes", "policyname": "all", "cmd": "ALL",
                       "roles": "authenticated", "qual": "true", "with_check": "true"},
                      {"schemaname": "storage", "tablename": "objects", "policyname": "any", "cmd": "SELECT",
                       "roles": "authenticated", "qual": "(auth.uid() IS NOT NULL)", "with_check": ""}],
            grants=[{"table_name": "notes", "grantee": "anon", "privilege_type": "INSERT"}],
            functions=[{"proname": "f", "prosecdef": "t", "config": "", "returns": "int", "anon_exec": "t"},
                       {"proname": "trg", "prosecdef": "t", "config": "", "returns": "trigger", "anon_exec": "t"}],
            views=[{"relname": "v", "options": ""}],
            has_storage=[{"present": "t"}],
            buckets=[{"id": "pics", "public": "t", "file_size_limit": ""}]))
        got = " | ".join(titles(f))
        for needle in ("Table 'open' has no row-level security (live database)",
                       "Policy 'all' on 'notes' allows all rows (live database)",
                       "Storage policy 'any' is not limited to one bucket",
                       "Grant on 'notes' to anon goes beyond its policies (live database)",
                       "SECURITY DEFINER function 'f' has no fixed search_path (live database)",
                       "Function 'f' can be run by anonymous callers (live database)",
                       "View 'v' is not security_invoker (live database)",
                       "Storage bucket 'pics' is public (live database)",
                       "Storage bucket 'pics' has no file size limit (live database)"):
            self.assertIn(needle, got)
        self.assertNotIn("trg", got)  # trigger functions are not callable over the API
        self.assertTrue(all(x.target == "live database db.stg.co" for x in f if x.check == "supabase_audit"))

    def test_storage_is_skipped_when_the_schema_is_absent(self):
        calls = []

        def fetch(name):
            calls.append(name)
            return rows_for()(name)
        supabase_audit.live_findings("h", fetch)
        self.assertNotIn("buckets", calls)


class LaterBucketSettingTests(unittest.TestCase):
    """A bucket created without a limit is often fixed by a later migration. Found on a real project, where the
    later update was hidden inside a DO block as a quoted string."""
    INSERT = "insert into storage.buckets (id, name, public) values ('photos', 'photos', false);"
    DO_BLOCK = ("do $$ begin if exists (select 1 from information_schema.columns where column_name = 'file_size_limit') "
                "then execute 'update storage.buckets set file_size_limit = 52428800 where id = ''photos'''; "
                "end if; end $$;")

    def check(self, *sql):
        from guard.checks import db_access
        from guard.sqlscan import split_statements
        stmts = [("m.sql", s) for text in sql for s in split_statements(text)]
        return titles(db_access.storage_findings(stmts, db_access.later_bucket_settings(stmts)))

    def test_without_a_later_update_the_missing_limit_is_reported(self):
        self.assertEqual(self.check(self.INSERT), ["Storage bucket 'photos' has no file size limit"])

    def test_a_later_plain_update_counts(self):
        self.assertEqual(self.check(self.INSERT, "update storage.buckets set file_size_limit = 5242880 where id = 'photos';"), [])

    def test_a_later_update_inside_a_do_block_string_counts_exactly_like_the_real_project(self):
        self.assertEqual(self.check(self.INSERT, self.DO_BLOCK), [])

    def test_an_update_without_where_applies_to_every_bucket(self):
        self.assertEqual(self.check(self.INSERT, "update storage.buckets set file_size_limit = 1000;"), [])

    def test_setting_the_limit_to_null_does_not_count(self):
        self.assertEqual(len(self.check(self.INSERT, "update storage.buckets set file_size_limit = null where id = 'photos';")), 1)

    def test_a_limit_on_a_different_bucket_does_not_count(self):
        self.assertEqual(len(self.check(self.INSERT, "update storage.buckets set file_size_limit = 1000 where id = 'other';")), 1)

    def test_a_later_update_that_makes_a_public_bucket_private_counts(self):
        pub = "insert into storage.buckets (id, name, public, file_size_limit) values ('p', 'p', true, 100);"
        self.assertEqual(self.check(pub), ["Storage bucket 'p' is public"])
        self.assertEqual(self.check(pub, "update storage.buckets set public = false where id = 'p';"), [])
        self.assertEqual(self.check(pub, "update storage.buckets set public = true where id = 'p';"),
                         ["Storage bucket 'p' is public", "Storage bucket made public"])

    def test_the_whole_check_reads_across_files(self):
        from guard.checks import db_access
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / "supabase" / "migrations"
            m.mkdir(parents=True)
            (m / "0004.sql").write_text(self.INSERT)
            (m / "0021.sql").write_text(self.DO_BLOCK)
            found = [x.title for x in db_access.run(Config(source_dir=d), None) if "size limit" in x.title]
            self.assertEqual(found, [])
            (m / "0021.sql").unlink()
            found = [x.title for x in db_access.run(Config(source_dir=d), None) if "size limit" in x.title]
            self.assertEqual(found, ["Storage bucket 'photos' has no file size limit"])


class GrantMergeTests(unittest.TestCase):
    def test_one_finding_per_table_and_role_listing_every_privilege(self):
        from guard.checks import db_access
        grants = [("db", "notes", "anon", {p}) for p in ("select", "insert", "update", "delete")]
        f = db_access.grant_gaps(grants, {}, {"notes"})
        self.assertEqual(len(f), 1)
        self.assertIn("DELETE, INSERT, SELECT, UPDATE", f[0].detail)

    def test_different_roles_stay_separate(self):
        from guard.checks import db_access
        grants = [("db", "t", "anon", {"select"}), ("db", "t", "authenticated", {"select"})]
        self.assertEqual(len(db_access.grant_gaps(grants, {}, {"t"})), 2)


class SupabaseCheckTests(unittest.TestCase):
    def project(self, files):
        d = tempfile.TemporaryDirectory()
        for name, text in files.items():
            p = Path(d.name) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.addCleanup(d.cleanup)
        return d.name

    def test_not_applicable_without_any_supabase_files(self):
        with self.assertRaises(Skipped) as cm:
            supabase_audit.run(Config(source_dir=self.project({"app.py": "x=1"})), None)
        self.assertFalse(cm.exception.applicable)

    def test_a_supabase_project_with_nothing_to_read_is_skipped_with_reasons(self):
        src = self.project({"supabase/migrations/1.sql": "create table t (id int);"})
        with self.assertRaises(Skipped) as cm:
            supabase_audit.run(Config(source_dir=src), None)
        self.assertTrue(cm.exception.applicable)
        self.assertIn("advisors export not provided", cm.exception.reason)
        self.assertIn("leaked-password protection", cm.exception.reason)

    def test_config_toml_and_advisors_are_read_and_unprovided_parts_are_said(self):
        src = self.project({"supabase/config.toml": TomlAuditTests.WEAK, "adv.json": json.dumps(AdvisorImportTests.LINTS)})
        f = supabase_audit.run(Config(source_dir=src, supabase_advisors_file="adv.json"), None)
        self.assertGreaterEqual(len([x for x in f if x.check == "supabase_audit" and "coverage-note" not in x.tags]), 11)
        notes = [x.title for x in f if "coverage-note" in x.tags]
        self.assertIn("read: config.toml, advisors export", notes)
        self.assertTrue(any("live catalog audit not configured" in n for n in notes))

    def test_the_database_is_never_touched_when_live_checks_are_off(self):
        src = self.project({"supabase/config.toml": TomlAuditTests.GOOD})
        called = []
        cfg = Config(source_dir=src, db_audit_url="postgresql://u@db.stg.co/x", db_audit_allowed_hosts=["db.stg.co"])
        f = supabase_audit.run(cfg, None, psql=lambda *a: called.append(a) or [])
        self.assertEqual(called, [])
        self.assertTrue(any("live database audit is off" in x.title for x in f))

    def test_a_refused_host_stops_before_any_connection(self):
        src = self.project({"supabase/config.toml": TomlAuditTests.GOOD})
        called = []
        cfg = Config(source_dir=src, db_audit_url="postgresql://u@db.other.co/x", db_audit_allowed_hosts=["db.stg.co"])
        with self.assertRaises(ScopeError):
            supabase_audit.run(cfg, object(), psql=lambda *a: called.append(a) or [])
        self.assertEqual(called, [])

    def test_live_audit_runs_through_the_injected_runner(self):
        src = self.project({"supabase/config.toml": TomlAuditTests.GOOD})
        data = rows_for(tables=[{"relname": "open", "relrowsecurity": "f"}])
        cfg = Config(source_dir=src, db_audit_url="postgresql://u@localhost/x", db_audit_allowed_hosts=["localhost"])
        import shutil
        real = shutil.which
        shutil.which = lambda name, *a, **k: "/usr/bin/psql" if name == "psql" else real(name, *a, **k)
        try:
            f = supabase_audit.run(cfg, object(), psql=lambda url, sql: data(next(k for k, v in supabase_audit.QUERIES.items() if v == sql)))
        finally:
            shutil.which = real
        self.assertIn("Table 'open' has no row-level security (live database)", titles(f))
        self.assertIn("read: config.toml, live catalog", [x.title for x in f])


@unittest.skipUnless(os.environ.get("GUARD_TEST_DB_URL"), "set GUARD_TEST_DB_URL to a throwaway Postgres to run this")
class RealPostgresTests(unittest.TestCase):
    """Runs the real queries against a real (throwaway) Postgres. Never point this at anything you care about."""

    def test_the_built_in_queries_run_and_a_write_is_impossible(self):
        url = os.environ["GUARD_TEST_DB_URL"]
        for name, sql in supabase_audit.QUERIES.items():
            if name == "buckets":
                continue  # needs the storage schema
            self.assertIsInstance(supabase_audit.psql_rows(url, sql), list, name)
        p = subprocess.run(["psql", url, "-X", "-q", "-v", "ON_ERROR_STOP=1"],
                           input="BEGIN READ ONLY;\ncreate table guard_should_not_exist(x int);\nROLLBACK;\n",
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("read-only", p.stderr)


# ---- 5. production configuration lint ---------------------------------------------------------------------------
class ProdEnvTests(unittest.TestCase):
    ENV = """APP_ENV=production
DEBUG=true
DEMO_LOGIN_ENABLED=true
CORS_ORIGINS=*
JWT_SECRET=changeme
SESSION_SECRET=short
WHATSAPP_VERIFY_TOKEN=
PAYMENT_API_KEY=Zq8vN2mXk4Rt7LpW9sYb3HcD6fGj1AeU
PUBLIC_WEB_URL=http://localhost:5173
API_URL=http://api.acme.com
DATABASE_URL=postgresql://u:pw@db.x.co/postgres?sslmode=disable
ANON_KEY=abc
"""

    def test_each_problem_is_found(self):
        got = titles(prod_config.evaluate_env(".env.production", self.ENV))
        for needle in ("Debug mode is on in production config (DEBUG)",
                       "Demo or auth-bypass switch is on in production config (DEMO_LOGIN_ENABLED)",
                       "Wildcard CORS in production config (CORS_ORIGINS)",
                       "Default or placeholder secret in production config (JWT_SECRET)",
                       "Short secret in production config (SESSION_SECRET)",
                       "Production config points at localhost (PUBLIC_WEB_URL)",
                       "Plain http URL in production config (API_URL)",
                       "Database connection without TLS in production config (DATABASE_URL)"):
            self.assertIn(needle, got)

    def test_good_secrets_and_empty_values_are_fine(self):
        got = titles(prod_config.evaluate_env(".env.production", self.ENV))
        self.assertFalse(any("PAYMENT_API_KEY" in t or "WHATSAPP_VERIFY_TOKEN" in t or "ANON_KEY" in t for t in got))

    def test_values_are_never_printed(self):
        for f in prod_config.evaluate_env(".env.production", self.ENV):
            blob = json.dumps(f.to_dict())
            for secret in ("changeme", "Zq8vN2mXk4Rt7LpW9sYb3HcD6fGj1AeU", "pw@db"):
                self.assertNotIn(secret, blob)

    def test_a_development_env_file_is_left_alone(self):
        self.assertEqual(prod_config.evaluate_env(".env.example", "APP_ENV=dev # dev | prod\nDEBUG=true\nJWT_SECRET=changeme"), [])
        self.assertEqual(prod_config.evaluate_env(".env", "DEBUG=true"), [])

    def test_a_file_is_production_by_name_or_by_content(self):
        self.assertEqual(len(prod_config.evaluate_env(".env.prod", "DEBUG=1")), 1)
        self.assertEqual(len(prod_config.evaluate_env("deploy.env", "NODE_ENV=production\nDEBUG=true")), 1)
        self.assertEqual(len(prod_config.evaluate_env("staging.env", "NODE_ENV=staging\nDEBUG=true")), 0)

    def test_empty_values_and_odd_lines_do_not_crash(self):
        text = "APP_ENV=prod\nEMPTY=\nQUOTED=\"\"\n=novalue\nexport X='a b'\n# c\nnoequals\nK=\"unterminated\n"
        prod_config.evaluate_env(".env.production", text)  # the bug the first real run found: KEY= with no value

    def test_quotes_and_inline_comments_are_handled(self):
        got = prod_config.parse_env("A='x y' # c\nB=\"q\"\nC=plain # note\nexport D=1")
        self.assertEqual([(k, v) for _, k, v in got], [("A", "x y"), ("B", "q"), ("C", "plain"), ("D", "1")])


class ProdCodeTests(unittest.TestCase):
    def test_wildcard_cors_and_credentials(self):
        medium = prod_config.evaluate_code("app/main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])')
        self.assertEqual(sev(medium), ["medium"])
        high = prod_config.evaluate_code("app/main.py", 'allow_origins=["*"], allow_credentials=True')
        self.assertEqual(sev(high), ["high"])
        self.assertEqual(sev(prod_config.evaluate_code("server.js", "app.use(cors())")), ["medium"])
        self.assertEqual(sev(prod_config.evaluate_code("server.js", "cors({ origin: '*' })")), ["medium"])

    def test_scoped_cors_is_fine(self):
        self.assertEqual(prod_config.evaluate_code("app/main.py", "allow_origins=settings.cors_origin_list"), [])

    def test_debug_mode_in_settings_or_run_call(self):
        self.assertEqual(len(prod_config.evaluate_code("app/settings.py", "DEBUG = True")), 1)
        self.assertEqual(len(prod_config.evaluate_code("app.py", "from flask import Flask\napp.run(debug=True)")), 1)
        self.assertEqual(prod_config.evaluate_code("app/settings.py", "DEBUG = False"), [])

    def test_default_secret_in_code_is_reported_without_its_value(self):
        f = prod_config.evaluate_code("app/config.py", 'DEV_JWT_SECRET = "dev-only-change-me-dev-only-change-me"')
        self.assertEqual(titles(f), ["Default secret in code (DEV_JWT_SECRET)"])
        self.assertNotIn("dev-only", json.dumps(f[0].to_dict()))
        self.assertEqual(prod_config.evaluate_code("app/config.py", 'API_KEY = os.environ["API_KEY"]'), [])

    def test_demo_login_default_on(self):
        f = prod_config.evaluate_code("app/config.py", "    demo_login_enabled: bool = True")
        self.assertEqual(sev(f), ["low"])
        self.assertEqual(prod_config.evaluate_code("app/config.py", "    demo_login_enabled: bool = False"), [])

    def test_tests_are_ignored(self):
        for path in ("tests/test_app.py", "app/__tests__/a.test.ts", "web/src/x.spec.ts"):
            self.assertEqual(prod_config.evaluate_code(path, 'allow_origins=["*"]\nSECRET_KEY = "changeme"'), [], path)


class ProdDeployTests(unittest.TestCase):
    def test_missing_headers_in_netlify_config(self):
        f = prod_config.evaluate_deploy("netlify.toml", '[build]\ncommand = "npm run build"\n')
        self.assertEqual(len(f), 4)
        self.assertIn("Strict-Transport-Security is not configured in netlify.toml", titles(f))

    def test_configured_headers_are_fine(self):
        text = "Strict-Transport-Security: x\nX-Content-Type-Options: nosniff\nContent-Security-Policy: y\nReferrer-Policy: z"
        self.assertEqual(prod_config.evaluate_deploy("public/_headers", text), [])

    def test_other_files_are_not_deploy_config(self):
        self.assertEqual(prod_config.evaluate_deploy("package.json", "{}"), [])

    def test_missing_rate_limiting_for_login_routes_is_a_heuristic_finding(self):
        files = [("app/routes.py", '@router.post("/login")\ndef login(): ...'), ("requirements.txt", "fastapi\n")]
        f = prod_config.project_findings(files, [])
        self.assertIn("Login-style routes found but no rate limiting anywhere", titles(f))
        self.assertIn("Heuristic", f[0].detail)

    def test_rate_limiting_anywhere_silences_it(self):
        for hint in ("slowapi", "express-rate-limit", "limit_req_zone", "Flask-Limiter", "throttle_classes"):
            files = [("app/routes.py", '@router.post("/login")\ndef login(): ...'), ("requirements.txt", f"fastapi\n{hint}\n")]
            self.assertNotIn("Login-style routes found but no rate limiting anywhere", titles(prod_config.project_findings(files, [])), hint)

    def test_backend_without_any_security_header_handling(self):
        files = [("app/main.py", "from fastapi import FastAPI\napp = FastAPI()")]
        self.assertIn("No security-header handling found for the backend", titles(prod_config.project_findings(files, [])))
        with_mw = files + [("app/mw.py", "response.headers['X-Content-Type-Options'] = 'nosniff'")]
        self.assertEqual([t for t in titles(prod_config.project_findings(with_mw, [])) if "security-header" in t], [])

    def test_whole_check_over_a_temp_project_never_connects_anywhere(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".env.production").write_text("DEBUG=true\nJWT_SECRET=changeme\n")
            (Path(d) / "tests").mkdir()
            (Path(d) / "tests" / "t.py").write_text('SECRET = "changeme"')
            f = prod_config.run(Config(source_dir=d), None)  # http=None: it needs no network at all
            self.assertEqual(sorted(sev(f)), ["high", "high"])


# ---- 6. cross-tenant test across every route --------------------------------------------------------------------
SPEC = {"servers": [{"url": "https://x/api"}], "paths": {
    "/clients": {"get": {}},
    "/clients/{client_id}": {"get": {}, "patch": {}, "delete": {}, "put": {}},
    "/clients/{client_id}/photos/{photo_id}": {"get": {"responses": {"200": {"content": {"image/jpeg": {}}}}}},
    "/clients/{client_id}/notes": {"get": {}, "post": {}},
    "/orders/{order_id}": {"get": {}},
}}


def tenant_cfg(**kw):
    return Config(base_url="https://s.acme.dev", tenant_a_token="A", tenant_b_token="B", openapi_file="spec.json",
                  tenant_a_resources=["/api/clients/c1", "/api/clients/c1/photos/p1"], **kw)


class TenantRoutesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        (Path(self.tmp.name) / "spec.json").write_text(json.dumps(SPEC))
        self.addCleanup(self.tmp.cleanup)

    def run_check(self, responder, **kw):
        cfg = tenant_cfg(source_dir=self.tmp.name, **kw)
        http = FakeHTTP(responder)
        return tenant_routes.run(cfg, http), http

    @staticmethod
    def safe(method, url, headers, body):
        who = headers.get("Authorization", "")
        if who == "Bearer A":
            return 200, {}, '[{"id": 1}]'
        return (401 if not who else 404), {}, ""

    def test_isolated_app_has_no_findings_but_a_summary_note(self):
        f, http = self.run_check(self.safe)
        self.assertEqual([x for x in f if "coverage-note" not in x.tags], [])
        note = next(x.title for x in f if "coverage-note" in x.tags)
        self.assertIn("3 read and 0 write route(s)", note)
        self.assertIn("write route(s) NOT tried (tenant_write_checks is off)", note)

    def test_urls_are_built_from_learned_ids_and_the_api_prefix(self):
        _, http = self.run_check(self.safe)
        urls = {c[1] for c in http.calls}
        self.assertIn("https://s.acme.dev/api/clients/c1", urls)
        self.assertIn("https://s.acme.dev/api/clients/c1/photos/p1", urls)
        self.assertIn("https://s.acme.dev/api/clients/c1/notes", urls)

    def test_routes_needing_unknown_ids_are_skipped_and_named(self):
        f, http = self.run_check(self.safe)
        self.assertFalse(any("/orders/" in c[1] for c in http.calls))
        self.assertIn("order_id", next(x.title for x in f if "coverage-note" in x.tags))

    def test_given_ids_make_more_routes_testable(self):
        f, http = self.run_check(self.safe, tenant_a_ids={"order_id": "o9"})
        self.assertTrue(any(c[1].endswith("/orders/o9") for c in http.calls))

    def test_every_read_is_tried_as_a_and_b_and_anonymous(self):
        _, http = self.run_check(self.safe)
        who = [c[2].get("Authorization", "-") for c in http.calls if c[1].endswith("/clients/c1")]
        self.assertEqual(sorted(who), ["-", "Bearer A", "Bearer B"])

    def test_a_leak_through_a_read_route_is_critical(self):
        def leaky(method, url, headers, body):
            return 200, {}, '[{"id": 1, "name": "secret client"}]'
        f, _ = self.run_check(leaky)
        self.assertIn("Cross-tenant data access on GET /clients/{client_id}", titles(f))
        self.assertIn("GET /clients/{client_id} readable without authentication", titles(f))

    def test_file_routes_are_named_as_such(self):
        def leaky(method, url, headers, body):
            return 200, {}, "\xff\xd8binary-jpeg-bytes"
        f, _ = self.run_check(leaky)
        photo = next(x for x in f if "photos" in x.title and x.severity == "critical")
        self.assertIn("file or signed-link route", photo.detail)

    def test_empty_200_for_the_other_tenant_is_not_a_leak(self):
        def rls(method, url, headers, body):
            return (200, {}, '[{"id": 1}]') if headers.get("Authorization") == "Bearer A" else (200, {}, "[]")
        f, _ = self.run_check(rls)
        self.assertNotIn("critical", sev(f))

    def test_when_the_owner_gets_nothing_the_route_is_inconclusive(self):
        f, _ = self.run_check(lambda *a: (200, {}, "[]"))
        self.assertTrue(all(x.severity == "info" for x in f))

    def test_writes_are_not_sent_unless_turned_on(self):
        _, http = self.run_check(self.safe)
        self.assertEqual({c[0] for c in http.calls}, {"GET"})

    def test_writes_run_as_b_with_delete_last(self):
        _, http = self.run_check(self.safe, tenant_write_checks=True)
        writes = [c for c in http.calls if c[0] != "GET"]
        self.assertEqual({c[0] for c in writes}, {"PUT", "PATCH", "POST", "DELETE"})
        self.assertTrue(all(c[2] == {"Authorization": "Bearer B"} for c in writes))
        order = [c[0] for c in writes]
        self.assertEqual(order[-1], "DELETE")
        self.assertLess(max(i for i, m in enumerate(order) if m != "DELETE"), order.index("DELETE"))

    def test_a_successful_write_by_the_other_tenant_is_critical_and_says_restore(self):
        def broken(method, url, headers, body):
            if method != "GET" and headers.get("Authorization") == "Bearer B":
                return 200, {}, "{}"
            return self.safe(method, url, headers, body)
        f, _ = self.run_check(broken, tenant_write_checks=True)
        hit = [x for x in f if x.severity == "critical"]
        self.assertEqual(len(hit), 4)  # PUT, PATCH and DELETE on the client, POST on its notes
        self.assertTrue(all("restore your staging data" in x.detail for x in hit))

    def test_a_422_is_inconclusive_and_points_at_tenant_write_bodies(self):
        def validate(method, url, headers, body):
            return (422, {}, "{}") if method != "GET" else self.safe(method, url, headers, body)
        f, _ = self.run_check(validate, tenant_write_checks=True)
        info = [x for x in f if "rejected the body first" in x.title]
        self.assertTrue(info)
        self.assertIn("tenant_write_bodies", info[0].detail)
        self.assertNotIn("critical", sev(f))

    def test_a_supplied_body_is_used(self):
        _, http = self.run_check(self.safe, tenant_write_checks=True,
                                 tenant_write_bodies={"PATCH /clients/{client_id}": {"name": "x"}})
        patch = next(c for c in http.calls if c[0] == "PATCH")
        self.assertEqual(patch[3], {"name": "x"})

    def test_server_errors_on_foreign_ids_are_flagged(self):
        def err(method, url, headers, body):
            return (500, {}, "") if method != "GET" else self.safe(method, url, headers, body)
        f, _ = self.run_check(err, tenant_write_checks=True)
        self.assertIn("medium", sev(f))

    def test_needs_both_tokens_and_resources(self):
        with self.assertRaises(Skipped):
            tenant_routes.run(Config(base_url="https://s.dev"), FakeHTTP(self.safe))

    def test_the_same_token_for_both_tenants_is_refused_and_nothing_is_sent(self):
        from guard.checks import tenant
        cfg = tenant_cfg(source_dir=self.tmp.name, tenant_write_checks=True)
        cfg.tenant_b_token = cfg.tenant_a_token
        for check in (tenant_routes.run, tenant.run):
            http = FakeHTTP(self.safe)
            with self.assertRaises(Skipped) as cm:
                check(cfg, http)
            self.assertIn("same token", cm.exception.reason)
            self.assertEqual(http.calls, [], "must not send a single request (a write would hit the owner's own data)")

    def test_schema_fetched_over_http_when_no_file_is_given(self):
        def serve(method, url, headers, body):
            if url.endswith("/openapi.json"):
                return 200, {}, json.dumps(SPEC)
            return self.safe(method, url, headers, body)
        cfg = Config(base_url="https://s.acme.dev", tenant_a_token="A", tenant_b_token="B", tenant_a_resources=["/api/clients/c1"])
        self.assertTrue(tenant_routes.run(cfg, FakeHTTP(serve)))

    def test_unreachable_or_invalid_schema_is_a_skip_with_a_reason(self):
        cfg = Config(base_url="https://s.acme.dev", tenant_a_token="A", tenant_b_token="B", tenant_a_resources=["/api/clients/c1"])
        with self.assertRaises(Skipped) as cm:
            tenant_routes.run(cfg, FakeHTTP(lambda *a: (404, {}, "")))
        self.assertIn("openapi", cm.exception.reason.lower())
        with self.assertRaises(Skipped):
            tenant_routes.run(cfg, FakeHTTP(lambda *a: (200, {}, "not json")))

    def test_config_rejects_bad_write_body_keys(self):
        with self.assertRaises(ValueError):
            Config(tenant_write_bodies={"GET /x": {}}).check_config()
        with self.assertRaises(ValueError):
            Config(tenant_write_bodies={"PATCHclients": {}}).check_config()

    def test_openapi_operations(self):
        ops = {o.key: o for o in openapi.operations(SPEC)}
        self.assertIn("DELETE /clients/{client_id}", ops)
        self.assertNotIn("GET /clients", ops)  # no id in the path
        self.assertTrue(ops["GET /clients/{client_id}/photos/{photo_id}"].file_like)
        self.assertFalse(ops["GET /orders/{order_id}"].file_like)


# ---- 7. launch readiness ------------------------------------------------------------------------------------------
class ReadinessTests(unittest.TestCase):
    def test_everything_starts_open_and_not_ready(self):
        its = readiness.items({})
        self.assertEqual(len(its), 5)
        self.assertFalse(readiness.is_ready(its))
        self.assertIn("NOT READY", readiness.status_line(its))
        self.assertEqual({i.id for i in its}, {"independent_review", "error_alerts", "backups_restore", "incident_plan", "breach_contacts"})

    def test_the_required_topics_are_all_present(self):
        titles_ = {k: t.lower() for k, (t, _) in readiness.ITEMS.items()}
        self.assertIn("independent human review", titles_["independent_review"])
        self.assertIn("penetration test", titles_["independent_review"])
        self.assertIn("alerts", titles_["error_alerts"])
        self.assertIn("backups", titles_["backups_restore"])
        self.assertIn("restore has been tested", titles_["backups_restore"])
        self.assertIn("incident plan", titles_["incident_plan"])
        self.assertIn("notify if data leaks", titles_["breach_contacts"])

    def sign(self, **kw):
        return readiness.validate({k: {"by": "adi", "date": "2026-11-12", **v} for k, v in kw.items()})

    def test_partial_signoff_stays_not_ready(self):
        its = readiness.items(self.sign(backups_restore={}))
        self.assertFalse(readiness.is_ready(its))
        self.assertIn("4 of 5", readiness.status_line(its))

    def test_all_signed_is_ready_but_says_guard_cannot_verify(self):
        its = readiness.items(self.sign(**{k: {} for k in readiness.ITEMS}))
        self.assertTrue(readiness.is_ready(its))
        self.assertIn("Guard cannot verify", readiness.status_line(its))
        self.assertTrue(all("not verified by guard" in l for l in readiness.to_markdown(its) if l.startswith("- [signed")))

    def test_expired_signoff_reopens_the_item(self):
        past = (date.today() - timedelta(days=1)).isoformat()
        its = readiness.items(self.sign(incident_plan={"expires": past}))
        item = next(i for i in its if i.id == "incident_plan")
        self.assertFalse(item.signed_off)
        self.assertTrue(item.expired)
        self.assertIn("Sign-off expired", " ".join(readiness.to_markdown(its)))

    def test_validation(self):
        for bad in ({"nope": {"by": "a", "date": "2026-01-01"}}, {"backups_restore": {"by": "a"}},
                    {"backups_restore": {"date": "2026-01-01"}}, {"backups_restore": {"by": "a", "date": "soon"}},
                    {"backups_restore": {"by": "a", "date": "2026-01-01", "extra": 1}}, {"backups_restore": "yes"},
                    {"backups_restore": True}):
            with self.assertRaises(ValueError, msg=str(bad)):
                readiness.validate(bad)

    def test_a_bare_true_cannot_sign_anything_off(self):
        with self.assertRaises(ValueError):
            Config.load(self._cfg({"launch_signoffs": {"incident_plan": True}}))

    def _cfg(self, d):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        p = Path(self._t.name) / "c.json"
        p.write_text(json.dumps(d))
        return str(p)

    def test_every_report_ends_with_the_manual_items_and_never_marks_them_passed(self):
        code, out, _, files = run_cli(["scan", "--no-live", "--only", "db_rules"], cfg=DEFAULT_CONFIG)
        for name in ("report.md", "summary.md"):
            text = files[name]
            self.assertIn("Launch readiness: manual items", text, name)
            self.assertIn("NOT READY TO LAUNCH. 5 of 5", text, name)
            self.assertEqual(text.count("- [ ] **"), 5, name)
            self.assertNotIn("[x]", text, name)
        self.assertTrue(files["report.md"].rstrip().endswith("")) and self.assertLess(
            files["report.md"].index("## Launch readiness"), len(files["report.md"]))
        self.assertIn('"ready": false', files["report.json"])
        self.assertIn("Launch readiness: NOT READY", out)

    def test_owner_signoffs_show_in_the_report_and_change_the_count(self):
        cfg = {**DEFAULT_CONFIG, "launch_signoffs": {"backups_restore": {"by": "adi", "date": "2026-11-12", "note": "restored to scratch"}}}
        _, _, _, files = run_cli(["scan", "--no-live", "--only", "db_rules"], cfg=cfg)
        self.assertIn("4 of 5", files["summary.md"])
        self.assertIn("signed off by adi on 2026-11-12; not verified by guard", files["summary.md"])

    def test_fix_tasks_forbid_the_agent_from_signing_off(self):
        with tempfile.TemporaryDirectory() as d:
            text = write_fix_tasks(d, record_run(d, [Finding("x", "high", "t", "d")], "high")).read_text()
            self.assertIn("Never sign off a launch-readiness item yourself", text)


# ---- 8. smaller improvements --------------------------------------------------------------------------------------
class SkippedLastTimeTests(PatchedScanners):
    def test_checks_skipped_last_time_are_listed_first_next_time(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                Path("guard.config.json").write_text(json.dumps(DEFAULT_CONFIG))
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    cli.main(["scan", "--no-live"])
                    first = Path("guard_out/summary.md").read_text()
                    self.assertNotIn("Skipped last time", first)  # nothing before it
                    cli.main(["scan", "--no-live"])
                second = Path("guard_out/summary.md").read_text()
                report = Path("guard_out/report.md").read_text()
                self.assertIn("## Skipped last time", second)
                self.assertIn("semgrep (code scan): STILL SKIPPED", second)
                self.assertLess(second.index("## Skipped last time"), second.index("## What ran"))
                self.assertLess(report.index("## Skipped last time"), report.index("## What ran"))
            finally:
                os.chdir(old)

    def test_a_check_that_ran_this_time_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            record_run(d, [], "high", coverage=[Coverage("tenant", "skipped", "no token")])
            res = record_run(d, [], "high", coverage=[Coverage("tenant", "ran")])
            text = write_summary(d, res, "high").read_text()
            self.assertIn("tenant: ran this time (was: no token)", text)

    def test_nothing_skipped_means_no_section(self):
        with tempfile.TemporaryDirectory() as d:
            record_run(d, [], "high", coverage=[Coverage("a", "ran")])
            self.assertNotIn("Skipped last time", write_summary(d, record_run(d, [], "high", coverage=[Coverage("a", "ran")]), "high").read_text())


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True, capture_output=True)


class DiffTests(unittest.TestCase):
    def repo(self, branch="trunk"):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        git(d, "init", "-q", "-b", branch)
        (Path(d) / "db").mkdir()
        (Path(d) / "db" / "old.sql").write_text("create table old_t (id int);")  # an unrelated, unprotected table
        (Path(d) / "db" / "ctx.sql").write_text("create table ctx_t (id int);")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "one")
        return d

    def scan(self, d, *argv):
        old = os.getcwd()
        os.chdir(d)
        filesmod.CHANGED = None
        try:
            Path("guard.config.json").write_text(json.dumps({**DEFAULT_CONFIG, "fail_on": "medium"}))
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(["scan", "--no-live", "--only", "db_rules", "-o", "gout", *argv])
            return code, out.getvalue(), err.getvalue(), json.loads(Path("gout/report.json").read_text()) if Path("gout/report.json").exists() else None
        finally:
            filesmod.CHANGED = None
            os.chdir(old)

    def test_only_changed_files_are_reported(self):
        d = self.repo()
        (Path(d) / "db" / "new.sql").write_text("create table new_t (id int);")
        code, out, _, rep = self.scan(d, "--diff-since", "HEAD")
        targets = {f["target"] for f in rep["findings"]}
        self.assertEqual({Path(t).name for t in targets}, {"new.sql"})  # old.sql and ctx.sql have the same problem but did not change

    def test_whole_project_context_still_applies_to_a_changed_file(self):
        d = self.repo()
        (Path(d) / "db" / "new.sql").write_text("create table new_t (id int);")
        (Path(d) / "db" / "rls.sql").write_text("alter table new_t enable row level security;")  # unchanged? no: also new
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "two")
        (Path(d) / "db" / "new.sql").write_text("create table new_t (id int); -- edited")
        _, _, _, rep = self.scan(d, "--diff-since", "HEAD")
        self.assertEqual([f["title"] for f in rep["findings"]], [])  # RLS is enabled in the unchanged file

    def test_without_the_flag_everything_is_reported(self):
        d = self.repo()
        _, _, _, rep = self.scan(d)
        self.assertEqual(len(rep["findings"]), 2)

    def test_bad_references_are_refused_with_exit_2(self):
        d = self.repo()
        for ref in ("nope", "HEAD; echo hi"):
            code, _, err, _ = self.scan(d, "--diff-since", ref)
            self.assertEqual(code, 2, ref)
            self.assertIn("--diff-since", err)
        # An option-looking value reaches guard only in the `=` form; guard refuses it. (In the spaced form argparse
        # itself rejects it before guard runs.)
        code, _, err, _ = self.scan(d, "--diff-since=--output=/tmp/x")
        self.assertEqual(code, 2)
        self.assertIn("not a valid commit reference", err)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            self.scan(d, "--diff-since", "--output=/tmp/x")
        self.assertEqual(cm.exception.code, 2)

    def test_not_a_git_repo_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, err, _ = self.scan(d, "--diff-since", "auto")
            self.assertEqual(code, 2)

    def test_untracked_new_files_count_as_changed(self):
        d = self.repo()
        (Path(d) / "db" / "brand_new.sql").write_text("create table b (id int);")
        names = {p.name for p in gitdiff.changed_files("HEAD", d)}
        self.assertIn("brand_new.sql", names)

    def test_base_ref_works_with_no_main_branch(self):
        d = self.repo(branch="trunk")
        (Path(d) / "x.txt").write_text("1")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "two")
        ref, why = gitdiff.base_ref(d)
        self.assertEqual(ref, "HEAD~1")  # on the only branch: the previous commit
        git(d, "checkout", "-q", "-b", "feature")
        (Path(d) / "y.txt").write_text("1")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "three")
        ref, why = gitdiff.base_ref(d)
        self.assertTrue(ref and why)  # there is still a usable base (a branch named trunk is not a known name: first commit)
        self.assertNotEqual(ref, "HEAD")

    def test_base_ref_prefers_the_fork_point_from_main_when_it_exists(self):
        d = self.repo(branch="main")
        fork = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
        git(d, "checkout", "-q", "-b", "feat")
        (Path(d) / "z.txt").write_text("1")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "feat work")
        self.assertEqual(gitdiff.base_ref(d)[0], fork)

    def test_diff_base_command(self):
        d = self.repo(branch="main")
        (Path(d) / "x.txt").write_text("1")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "two")
        old = os.getcwd()
        os.chdir(d)
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["diff-base"]), 0)
            self.assertEqual(out.getvalue().strip(), "HEAD~1")
        finally:
            os.chdir(old)

    def test_walk_filters_to_changed_files_unless_all_files_is_asked_for(self):
        d = self.repo()
        filesmod.CHANGED = {(Path(d) / "db" / "old.sql").resolve()}
        try:
            self.assertEqual([p.name for p in filesmod.walk(d, (".sql",))], ["old.sql"])
            self.assertEqual(len(list(filesmod.walk(d, (".sql",), all_files=True))), 2)
        finally:
            filesmod.CHANGED = None


if __name__ == "__main__":
    unittest.main()
