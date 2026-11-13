"""Tests for the feedback round: accuracy (A), visible coverage (B), live-scan noise (C), API styles and static
SQL checks (D), and setup safety (E)."""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from guard import accept, cli
from guard.bodies import is_empty_body
from guard.checks import access, db_access, db_rules, headers, injection, ratelimit, tenant, upload
from guard.config import DEFAULT_CONFIG, Config
from guard.coverage import Coverage, Skipped
from guard.findings import Finding
from guard.loop import record_run, write_fix_tasks, write_summary
from guard.sqlscan import split_statements


def titles(findings):
    return [f.title for f in findings]


def sev(findings):
    return [f.severity for f in findings]


# ---- A1/A2: policies are judged by command and role ---------------------------------------------------------------
class PolicyTests(unittest.TestCase):
    def one(self, policy):
        return db_rules.open_policies("m.sql", policy)

    def test_anonymous_read_only_catalog_is_low(self):
        f = self.one("create policy p on public.plans for select to anon using (true);")
        self.assertEqual(sev(f), ["low"])
        self.assertIn("accepted_risks", f[0].fix)

    def test_read_for_any_signed_in_user_stays_high(self):
        self.assertEqual(sev(self.one("create policy p on t for select to authenticated using (true);")), ["high"])

    def test_read_with_no_role_means_everyone_and_stays_high(self):
        self.assertEqual(sev(self.one("create policy p on t for select using (true);")), ["high"])

    def test_anon_and_authenticated_together_is_high(self):
        self.assertEqual(sev(self.one("create policy p on t for select to anon, authenticated using (true);")), ["high"])

    def test_all_commands_is_high_even_for_anon(self):
        self.assertEqual(sev(self.one("create policy p on t for all to anon using (true);")), ["high"])
        self.assertEqual(sev(self.one("create policy p on t to anon using (true);")), ["high"])  # FOR defaults to ALL

    def test_write_policies_are_high(self):
        self.assertEqual(sev(self.one("create policy p on t for insert to anon with check (true);")), ["high"])
        self.assertEqual(sev(self.one("create policy p on t for update to anon using (true);")), ["high"])
        self.assertEqual(sev(self.one("create policy p on t for delete to anon using (true);")), ["high"])

    def test_service_role_only_is_info(self):
        self.assertEqual(sev(self.one("create policy p on t for all to service_role using (true);")), ["info"])

    def test_scoped_policy_is_not_flagged(self):
        self.assertEqual(self.one("create policy p on t for select to authenticated using (owner = auth.uid());"), [])
        self.assertEqual(self.one("create policy p on t for insert to authenticated with check (owner = auth.uid());"), [])

    def test_fix_text_does_not_assume_multi_tenancy(self):
        f = self.one("create policy p on t for all to authenticated using (true);")[0]
        self.assertNotIn("tenant_id", f.fix)
        self.assertIn("accepted_risks", f.fix)

    def test_missing_rls_fix_offers_accepting_it(self):
        f = db_rules.evaluate_sql("m.sql", "create table notes (id int);", high=True)[0]
        self.assertIn("accepted_risks", f.fix)

    def test_policy_in_a_statement_with_semicolon_in_string_still_parses(self):
        sql = "create policy \"a;b\" on t for select to anon using (true); create table u (id int);"
        self.assertEqual(sev(self.one(sql)), ["low"])


# ---- A3: accepted risks ---------------------------------------------------------------------------------------------
class AcceptTests(unittest.TestCase):
    F = Finding("db_rules", "high", "Table 'plans' has no row-level security", "d", "supabase/migrations/0001.sql")

    def entry(self, **kw):
        base = {"check": "db_rules", "title": "Table 'plans'*", "reason": "public catalog", "owner": "adi"}
        return accept.validate([{**base, **kw}])

    def test_requires_reason_and_owner(self):
        for missing in ("reason", "owner", "check"):
            with self.assertRaises(ValueError):
                self.entry(**{missing: ""})

    def test_cannot_accept_a_whole_check(self):
        with self.assertRaises(ValueError):
            accept.validate([{"check": "db_rules", "reason": "r", "owner": "o"}])

    def test_bad_date_and_unknown_key_are_errors(self):
        with self.assertRaises(ValueError):
            self.entry(expires="next week")
        with self.assertRaises(ValueError):
            self.entry(ignore=True)

    def test_matching_finding_moves_to_accepted(self):
        active, acc, notes = accept.apply([self.F], self.entry())
        self.assertEqual((active, len(acc), notes), ([], 1, []))
        self.assertEqual((acc[0].reason, acc[0].owner), ("public catalog", "adi"))

    def test_other_findings_stay_active(self):
        other = Finding("db_rules", "high", "Table 'notes' has no row-level security", "d")
        active, acc, _ = accept.apply([self.F, other], self.entry())
        self.assertEqual(active, [other])

    def test_target_glob(self):
        active, acc, _ = accept.apply([self.F], self.entry(title="", target="supabase/*"))
        self.assertEqual(len(acc), 1)

    def test_expired_acceptance_blocks_again_and_says_so(self):
        past = (date.today() - timedelta(days=1)).isoformat()
        active, acc, notes = accept.apply([self.F], self.entry(expires=past))
        self.assertEqual((active, acc), ([self.F], []))
        self.assertIn("expired", notes[0])

    def test_future_expiry_applies(self):
        future = (date.today() + timedelta(days=30)).isoformat()
        self.assertEqual(len(accept.apply([self.F], self.entry(expires=future))[1]), 1)

    def test_entry_that_matches_nothing_is_reported(self):
        _, _, notes = accept.apply([], self.entry())
        self.assertIn("matches nothing", notes[0])

    def test_accepted_risk_does_not_block_but_is_never_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            active, acc, _ = accept.apply([self.F], self.entry())
            res = record_run(d, active, "high", accepted=acc)
            self.assertTrue(res["clean"])
            write_summary(d, res, "high")
            write_fix_tasks(d, res)
            summary = (Path(d) / "summary.md").read_text()
            self.assertIn("Accepted risks", summary)
            self.assertIn("public catalog", summary)
            self.assertIn("adi", summary)
            self.assertIn("Accepted risks", (Path(d) / "fix_tasks.md").read_text())

    def test_a_blocking_finding_that_is_later_accepted_is_not_called_fixed(self):
        with tempfile.TemporaryDirectory() as d:
            record_run(d, [self.F], "high")
            active, acc, _ = accept.apply([self.F], self.entry())
            res = record_run(d, active, "high", accepted=acc)
            self.assertEqual(res["fixed"], [])

    def test_fix_tasks_tell_the_agent_not_to_accept_risks_itself(self):
        with tempfile.TemporaryDirectory() as d:
            res = record_run(d, [self.F], "high")
            text = write_fix_tasks(d, res).read_text()
            self.assertIn("accepted_risks", text)
            self.assertIn("instead of adding it yourself", text)

    def test_config_loads_and_validates_accepted_risks(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"accepted_risks": [{"check": "x", "title": "t", "reason": "r", "owner": ""}]}))
            with self.assertRaises(ValueError):
                Config.load(str(p))


# ---- A4: 200 with an empty body is not a leak -----------------------------------------------------------------------
class EmptyBodyTests(unittest.TestCase):
    def test_what_counts_as_empty(self):
        for empty in ("", "  ", "[]", "{}", "null", '""', '{"data": [], "error": null}', '[[], {}]'):
            self.assertTrue(is_empty_body(empty), empty)
        for data in ('[{"id": 1}]', '{"id": 1}', "<html>hi</html>", "forbidden", '{"count": 0}', '{"ok": true}'):
            self.assertFalse(is_empty_body(data), data)

    def test_rls_style_empty_200_for_other_tenant_is_not_critical(self):
        f = tenant.evaluate("u", 200, 401, 200, "[]", anon_body="", a_body='[{"id":1}]')
        self.assertNotIn("critical", sev(f))
        self.assertTrue(any("empty" in t for t in titles(f)))

    def test_real_data_for_other_tenant_is_still_critical(self):
        f = tenant.evaluate("u", 200, 401, 200, '[{"id": 1}]', anon_body="", a_body='[{"id":1}]')
        self.assertIn("Cross-tenant data access (IDOR)", titles(f))

    def test_anonymous_empty_200_is_not_critical_but_data_is(self):
        self.assertNotIn("critical", sev(tenant.evaluate("u", 200, 200, 403, "", "[]", '[{"id":1}]')))
        self.assertIn("critical", sev(tenant.evaluate("u", 200, 200, 403, "", '[{"id":1}]', '[{"id":1}]')))

    def test_when_the_owner_gets_nothing_the_test_proves_nothing(self):
        f = tenant.evaluate("u", 200, 401, 200, "[]", anon_body="", a_body="[]")
        self.assertEqual(sev(f), ["info"])

    def test_status_only_callers_keep_the_old_behaviour(self):
        self.assertIn("critical", sev(tenant.evaluate("u", 200, 401, 200, "x")))


# ---- A5: roles mode ---------------------------------------------------------------------------------------------------
class FakeHTTP:
    def __init__(self, responder):
        self.responder, self.calls, self.last_set_cookies = responder, [], []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.responder(method, url, headers or {}, body)


class AccessTests(unittest.TestCase):
    R = {"name": "client cannot list staff", "path": "/staff", "caller": "client", "expect": "denied"}

    def test_denied_rule(self):
        self.assertEqual(access.evaluate(self.R, "u", 403, "no"), [])
        self.assertEqual(access.evaluate(self.R, "u", 404, ""), [])
        self.assertEqual(access.evaluate(self.R, "u", 200, "[]"), [])  # filtered to nothing: safe
        f = access.evaluate(self.R, "u", 200, '[{"name": "Neha"}]')
        self.assertEqual(sev(f), ["critical"])

    def test_empty_rule(self):
        r = {**self.R, "expect": "empty"}
        self.assertEqual(access.evaluate(r, "u", 200, "[]"), [])
        self.assertEqual(sev(access.evaluate(r, "u", 200, '[{"x":1}]')), ["critical"])

    def test_allowed_rule_catches_a_broken_route_or_token(self):
        r = {**self.R, "expect": "allowed", "caller": "staff"}
        self.assertEqual(access.evaluate(r, "u", 200, '[{"x":1}]'), [])
        self.assertEqual(sev(access.evaluate(r, "u", 401, "")), ["medium"])
        self.assertEqual(sev(access.evaluate(r, "u", 200, "[]")), ["low"])

    def test_network_failure_is_inconclusive_not_a_pass(self):
        self.assertEqual(sev(access.evaluate(self.R, "u", 0, "request failed")), ["info"])

    def run_cfg(self, rules, tokens, responder):
        cfg = Config(base_url="https://s.acme.dev", tokens=tokens, access_checks=rules)
        http = FakeHTTP(responder)
        return access.run(cfg, http), http

    def test_run_uses_the_callers_own_token_and_none_for_anonymous(self):
        rules = [{**self.R}, {"path": "/public", "caller": "anonymous", "expect": "allowed"}]
        found, http = self.run_cfg(rules, {"client": "CT"}, lambda *a: (200, {}, '[{"x":1}]'))
        self.assertEqual(sev(found), ["critical"])  # the client got staff data
        self.assertEqual(http.calls[0][2], {"Authorization": "Bearer CT"})
        self.assertEqual(http.calls[1][2], {})

    def test_no_rules_is_a_visible_skip(self):
        with self.assertRaises(Skipped):
            access.run(Config(base_url="https://s.acme.dev"), FakeHTTP(lambda *a: (200, {}, "")))

    def test_unset_token_skips_that_caller_and_says_so(self):
        found, _ = self.run_cfg([self.R, {"path": "/x", "caller": "staff", "expect": "allowed"}],
                                {"client": "CT", "staff": ""}, lambda *a: (403, {}, ""))
        self.assertEqual(found[-1].tags, ["coverage-note"])
        self.assertIn("staff", found[-1].title)

    def test_all_tokens_unset_is_a_skip(self):
        with self.assertRaises(Skipped):
            self.run_cfg([self.R], {"client": ""}, lambda *a: (403, {}, ""))

    def test_config_validation(self):
        base = dict(base_url="https://s.acme.dev", tokens={"client": "t"})
        for bad in ({"path": "/x", "expect": "maybe"}, {"expect": "denied"}, {"path": "/x", "expect": "denied", "caller": "ghost"}):
            with self.assertRaises(ValueError):
                Config(**base, access_checks=[bad]).check_config()


# ---- B: coverage is visible ---------------------------------------------------------------------------------------
def make_cfg(**kw):
    return Config(base_url="https://s.acme.dev", allowed_hosts=["s.acme.dev"], **kw)


class CoverageTests(unittest.TestCase):
    def run_stages(self, cfg, http=None):
        with tempfile.TemporaryDirectory() as d:
            cfg.source_dir = d
            return cli._run_stages(cfg, {"static", *cli.ALL_CHECKS}, http)

    def status(self, coverage):
        return {c.name: (c.status, c.detail) for c in coverage}

    def test_offline_marks_live_checks_off_and_missing_scanners_skipped(self):
        _, _, cov, _ = self.run_stages(make_cfg())
        st = self.status(cov)
        self.assertEqual(st["tenant"][0], "off")
        self.assertEqual(st["headers"][0], "off")
        self.assertEqual(st["db_rules"][0], "n/a")  # no .sql files in the empty folder

    def test_live_unconfigured_checks_are_reported_as_skipped_with_the_reason(self):
        _, _, cov, _ = self.run_stages(make_cfg(), FakeHTTP(lambda *a: (200, {}, "")))
        st = self.status(cov)
        for name in ("tenant", "access", "injection", "mass_assignment", "upload", "ratelimit"):
            self.assertEqual(st[name][0], "skipped", name)
            self.assertTrue(st[name][1], name)
        self.assertIn("rate_limit_path", st["ratelimit"][1])  # item 7: no silent disappearance

    def test_summary_never_says_clean_when_a_scanner_did_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            cov = [Coverage("gitleaks (secret scan)", "skipped", "not installed")]
            res = record_run(d, [], "high", coverage=cov)
            text = write_summary(d, res, "high").read_text()
            self.assertTrue(res["clean"] and not res["complete"])
            self.assertNotIn("**Status:** CLEAN", text)
            self.assertIn("NOT A FULL CLEAN", text)
            self.assertIn("gitleaks (secret scan)", text)

    def test_summary_opens_with_the_coverage_table(self):
        with tempfile.TemporaryDirectory() as d:
            cov = [Coverage("db_rules", "ran"), Coverage("tenant", "skipped", "not set: tenant_a_token")]
            text = write_summary(d, record_run(d, [], "high", coverage=cov), "high").read_text()
            self.assertLess(text.index("| check | status | detail |"), text.index("What this did not check"))
            self.assertIn("| tenant | SKIPPED | not set: tenant_a_token |", text)

    def test_fully_covered_clean_scan_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            res = record_run(d, [], "high", coverage=[Coverage("db_rules", "ran"), Coverage("tenant", "off")])
            self.assertIn("**Status:** CLEAN.", write_summary(d, res, "high").read_text())

    def test_summary_is_written_even_with_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            res = record_run(d, [], "high", coverage=[])
            self.assertTrue(write_summary(d, res, "high").exists())

    def test_probe_cap_is_reported(self):
        paths = [f"/p{i}" for i in range(8)]
        _, _, cov, _ = self.run_stages(make_cfg(probe_paths=paths, injection_params=["q"]),
                                       FakeHTTP(lambda *a: (200, {"content-type": "application/json"}, "{}")))
        self.assertIn("first 5 of 8", self.status(cov)["headers"][1])

    def test_no_cap_note_when_everything_was_checked(self):
        _, _, cov, _ = self.run_stages(make_cfg(probe_paths=["/a", "/b"]),
                                       FakeHTTP(lambda *a: (200, {"content-type": "application/json"}, "{}")))
        self.assertNotIn("first", self.status(cov)["headers"][1])

    def test_ratelimit_unconfigured_raises_skipped(self):
        with self.assertRaises(Skipped):
            ratelimit.run(make_cfg(), FakeHTTP(lambda *a: (200, {}, "")))


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_scanners_config_and_missing_checks(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "guard.config.json"
            p.write_text(json.dumps(DEFAULT_CONFIG))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli.main(["doctor", "-c", str(p)])
            out = buf.getvalue()
            self.assertEqual(code, 0)
            for word in ("semgrep", "gitleaks", "trivy", "live scans: REFUSED", "NOT SET", "NOT CONFIGURED"):
                self.assertIn(word, out)

    def test_doctor_without_config_says_how_to_start(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["doctor", "-c", "/nonexistent/guard.config.json"]), 0)
        self.assertIn("guard init", buf.getvalue())


# ---- C: live-scan noise ---------------------------------------------------------------------------------------------
class HeaderNoiseTests(unittest.TestCase):
    def test_same_finding_on_many_paths_is_reported_once_per_host(self):
        cfg = make_cfg(probe_paths=["/", "/api/a", "/api/b", "/api/c"])
        http = FakeHTTP(lambda *a: (200, {"content-type": "text/html"}, ""))
        found = headers.run(cfg, http)
        self.assertEqual(len(titles(found)), len(set(titles(found))))
        self.assertLessEqual(len(found), 6)  # was 4 paths x 6 headers = 24
        csp = next(f for f in found if f.title == "Missing content-security-policy")
        self.assertEqual(csp.target, "https://s.acme.dev")
        self.assertIn("4 path(s)", csp.evidence)

    def test_page_only_headers_are_not_expected_on_json(self):
        found = headers.evaluate("https://x", {"content-type": "application/json"})
        self.assertNotIn("Missing content-security-policy", titles(found))
        self.assertNotIn("No clickjacking protection", titles(found))
        self.assertIn("Missing x-content-type-options", titles(found))

    def test_page_only_headers_are_expected_on_html(self):
        found = headers.evaluate("https://x", {"content-type": "text/html; charset=utf-8"})
        self.assertIn("Missing content-security-policy", titles(found))
        self.assertIn("No clickjacking protection", titles(found))

    def test_hsts_not_expected_on_plain_http_local_addresses(self):
        for url in ("http://127.0.0.1:8000", "http://localhost:5173", "http://[::1]/"):
            self.assertNotIn("Missing strict-transport-security", titles(headers.evaluate(url, {})), url)

    def test_hsts_still_expected_over_https_and_on_remote_hosts(self):
        self.assertIn("Missing strict-transport-security", titles(headers.evaluate("https://s.acme.dev", {})))
        self.assertIn("Missing strict-transport-security", titles(headers.evaluate("http://s.acme.dev", {})))

    def test_json_only_api_host_gets_few_findings(self):
        cfg = make_cfg(probe_paths=["/api/a", "/api/b", "/api/c", "/api/d"])
        found = headers.run(cfg, FakeHTTP(lambda *a: (200, {"content-type": "application/json"}, "{}")))
        self.assertLessEqual(len(found), 3)


# ---- D13/D14: other API styles, tokens per check ----------------------------------------------------------------
class InjectionTargetTests(unittest.TestCase):
    @staticmethod
    def vulnerable(method, url, headers, body):
        hit = "%27" in url or (isinstance(body, dict) and "'" in str(body.get("q", "")))
        return 200, {}, ("syntax error at or near \"'\"" if hit else "ok")

    def cfg(self, **kw):
        return make_cfg(tokens={"user": "UT"}, **kw)

    def test_filter_syntax_and_json_body_routes_are_probed(self):
        cfg = self.cfg(injection_targets=[{"path": "/rest/v1/items?name=eq.{payload}", "token": "user"},
                                          {"path": "/rpc/search", "method": "POST", "body": {"q": "{payload}"}}])
        http = FakeHTTP(self.vulnerable)
        found = injection.run(cfg, http)
        self.assertEqual(len(found), 2)
        self.assertTrue(all(f.severity == "high" for f in found))
        self.assertTrue(any(c[0] == "POST" and isinstance(c[3], dict) for c in http.calls))

    def test_clean_target_has_no_findings(self):
        cfg = self.cfg(injection_targets=[{"path": "/rpc/search", "method": "POST", "body": {"q": "{payload}"}}])
        self.assertEqual(injection.run(cfg, FakeHTTP(lambda *a: (200, {}, "ok"))), [])

    def test_fill_encodes_in_urls_but_not_in_json(self):
        self.assertEqual(injection.fill("/x?a={payload}", "1'", in_url=True), "/x?a=1%27")
        self.assertEqual(injection.fill({"q": ["{payload}"]}, "1'"), {"q": ["1'"]})

    def test_template_without_payload_is_a_config_error(self):
        with self.assertRaises(ValueError):
            self.cfg(injection_targets=[{"path": "/x"}]).check_config()

    def test_nothing_configured_is_a_visible_skip(self):
        with self.assertRaises(Skipped):
            injection.run(make_cfg(), FakeHTTP(lambda *a: (200, {}, "")))

    def test_each_check_can_use_its_own_token_or_none(self):
        cfg = make_cfg(tenant_a_token="A", tokens={"staff": "S"}, check_tokens={"injection": "anonymous", "upload": "staff"})
        self.assertEqual(cfg.auth_headers("injection"), {})
        self.assertEqual(cfg.auth_headers("upload"), {"Authorization": "Bearer S"})
        self.assertEqual(cfg.auth_headers("mass_assignment"), {"Authorization": "Bearer A"})  # default: tenant A

    def test_injection_param_probe_honours_anonymous(self):
        cfg = make_cfg(tenant_a_token="A", check_tokens={"injection": "anonymous"}, injection_params=["q"])
        http = FakeHTTP(lambda *a: (200, {}, "ok"))
        injection.run(cfg, http)
        self.assertTrue(all(c[2] == {} for c in http.calls))

    def test_unset_named_token_skips_instead_of_sending_unauthenticated(self):
        cfg = make_cfg(tokens={"staff": ""}, check_tokens={"upload": "staff"}, upload_path="/up")
        http = FakeHTTP(lambda *a: (200, {}, ""))
        with self.assertRaises(Skipped):
            upload.run(cfg, http)
        self.assertEqual(http.calls, [])

    def test_unknown_token_name_is_a_config_error(self):
        with self.assertRaises(ValueError):
            make_cfg(check_tokens={"upload": "ghost"}).check_config()

    def test_tokens_resolve_from_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"tokens": {"staff": "ENV:GUARD_TEST_STAFF"}}))
            os.environ["GUARD_TEST_STAFF"] = "secret"
            try:
                self.assertEqual(Config.load(str(p)).tokens["staff"], "secret")
            finally:
                del os.environ["GUARD_TEST_STAFF"]


# ---- D15: static SQL checks -----------------------------------------------------------------------------------------
def stmts(sql, path="supabase/migrations/1.sql"):
    return [(path, s) for s in split_statements(sql)]


class SqlScannerTests(unittest.TestCase):
    def test_semicolons_in_strings_comments_and_bodies_do_not_split(self):
        s = split_statements("select 'a;b'; -- x; y\nselect 2; /* ; */ create function f() returns int as $$ select 1; $$;")
        self.assertEqual(len(s), 3)
        self.assertIn("select 1;", s[2])


class FunctionTests(unittest.TestCase):
    DEFINER = "create function f() returns int language sql security definer as $$ select 1 $$;"

    def test_definer_without_search_path_is_high(self):
        f = db_access.function_findings(stmts(self.DEFINER + " revoke all on function f() from public, anon;"))
        self.assertEqual(titles(f), ["SECURITY DEFINER function 'f' has no fixed search_path"])

    def test_definer_with_search_path_and_revoke_is_clean(self):
        sql = ("create function f() returns int language sql security definer set search_path = '' as $$ select 1 $$;"
               " revoke all on function f() from public, anon;")
        self.assertEqual(db_access.function_findings(stmts(sql)), [])

    def test_search_path_set_after_the_body_is_recognised(self):
        sql = ("create function f() returns int as $$ select 1 $$ language sql security definer set search_path = public;"
               " revoke execute on function public.f() from public;")
        self.assertEqual(db_access.function_findings(stmts(sql)), [])

    def test_function_anyone_can_run(self):
        f = db_access.function_findings(stmts(
            "create function f() returns int language sql security definer set search_path = '' as $$ select 1 $$;"))
        self.assertEqual((titles(f), sev(f)), (["Function 'f' can be run by anyone"], ["high"]))

    def test_invoker_function_anyone_can_run_is_low(self):
        f = db_access.function_findings(stmts("create function g() returns int language sql as $$ select 1 $$;"))
        self.assertEqual(sev(f), ["low"])

    def test_trigger_functions_are_not_flagged(self):
        self.assertEqual(db_access.function_findings(stmts(
            "create function t() returns trigger language plpgsql as $$ begin return new; end $$;")), [])

    def test_blanket_revoke_covers_only_functions_created_before_it(self):
        sql = ("create function a() returns int language sql as $$ select 1 $$;"
               "revoke all on all functions in schema public from anon;"
               "create function b() returns int language sql as $$ select 1 $$;")
        self.assertEqual(titles(db_access.function_findings(stmts(sql))), ["Function 'b' can be run by anyone"])

    def test_default_privileges_revoke_covers_later_functions(self):
        sql = ("alter default privileges in schema public revoke execute on functions from public, anon;"
               "create function b() returns int language sql as $$ select 1 $$;")
        self.assertEqual(db_access.function_findings(stmts(sql)), [])

    def test_do_loop_that_revokes_counts_as_a_blanket(self):
        sql = ("create function a() returns int language sql as $$ select 1 $$;"
               "do $$ declare f text; begin for f in select 1 loop execute format('revoke all on function public.%s "
               "from public, anon', f); end loop; end $$;")
        self.assertEqual(db_access.function_findings(stmts(sql)), [])


class ViewTests(unittest.TestCase):
    def test_view_without_security_invoker(self):
        f = db_access.view_findings(stmts("create view v as select * from t;"))
        self.assertEqual((titles(f), sev(f)), (["View 'v' is not security_invoker"], ["high"]))
        self.assertEqual(sev(db_access.view_findings(stmts("create view v as select 1;", "db/1.sql"))), ["medium"])

    def test_security_invoker_view_is_clean(self):
        for sql in ("create view v with (security_invoker = true) as select 1;",
                    "create or replace view v with (security_invoker=on) as select 1;"):
            self.assertEqual(db_access.view_findings(stmts(sql)), [])

    def test_materialized_views_are_not_judged_by_this_rule(self):
        self.assertEqual(db_access.view_findings(stmts("create materialized view m as select 1;")), [])


class GrantTests(unittest.TestCase):
    POLICY = "create policy p on t for select to authenticated using (owner = auth.uid());"

    def test_write_grant_without_a_policy(self):
        f = db_access.grant_findings(stmts(self.POLICY + "grant select, insert on t to authenticated;"), {"t"})
        self.assertEqual(titles(f), ["Grant on 't' to authenticated goes beyond its policies"])
        self.assertIn("INSERT", f[0].detail)
        self.assertNotIn("SELECT", f[0].detail)

    def test_grants_that_match_policies_are_clean(self):
        self.assertEqual(db_access.grant_findings(stmts(self.POLICY + "grant select on t to authenticated;"), {"t"}), [])

    def test_all_policy_covers_every_privilege(self):
        sql = "create policy p on t for all to authenticated using (true);grant all on t to authenticated;"
        self.assertEqual(db_access.grant_findings(stmts(sql), {"t"}), [])

    def test_anon_grant_is_medium(self):
        f = db_access.grant_findings(stmts("grant select on t to anon;"), {"t"})
        self.assertEqual(sev(f), ["medium"])

    def test_table_without_rls_is_left_to_db_rules(self):
        self.assertEqual(db_access.grant_findings(stmts("grant all on t to anon;"), set()), [])

    def test_blanket_grant_to_anon(self):
        f = db_access.grant_findings(stmts("grant select on all tables in schema public to anon;"), set())
        self.assertEqual(titles(f), ["Blanket grant on all tables to anon"])
        revoked = db_access.grant_findings(stmts(
            "grant select on all tables in schema public to anon; revoke all on all tables in schema public from anon;"), set())
        self.assertEqual(revoked, [])

    def test_function_and_schema_grants_are_ignored(self):
        sql = "grant execute on function f() to anon; grant usage on schema public to anon;"
        self.assertEqual(db_access.grant_findings(stmts(sql), {"t"}), [])


class StorageTests(unittest.TestCase):
    def test_public_bucket(self):
        f = db_access.storage_findings(stmts(
            "insert into storage.buckets (id, name, public, file_size_limit) values ('pics', 'pics', true, 5000000);"))
        self.assertEqual(titles(f), ["Storage bucket 'pics' is public"])

    def test_private_bucket_is_clean(self):
        self.assertEqual(db_access.storage_findings(stmts(
            "insert into storage.buckets (id, name, public, file_size_limit) values ('pics', 'pics', false, 5000000) "
            "on conflict (id) do nothing;")), [])

    def test_bucket_without_a_size_limit(self):
        f = db_access.storage_findings(stmts(
            "insert into storage.buckets (id, name, public) values ('pics', 'pics', false);"))
        self.assertEqual((titles(f), sev(f)), (["Storage bucket 'pics' has no file size limit"], ["low"]))
        null = db_access.storage_findings(stmts(
            "insert into storage.buckets (id, name, public, file_size_limit) values ('pics', 'pics', false, null);"))
        self.assertEqual(len(null), 1)

    def test_public_bucket_without_a_limit_gets_both_findings(self):
        f = db_access.storage_findings(stmts("insert into storage.buckets (id, name, public) values ('p', 'p', true);"))
        self.assertEqual(sorted(sev(f)), ["low", "medium"])

    def test_bucket_made_public_later(self):
        self.assertEqual(len(db_access.storage_findings(stmts("update storage.buckets set public = true where id = 'x';"))), 1)

    def test_policy_without_a_bucket_condition(self):
        sql = "create policy p on storage.objects for select to authenticated using (auth.uid() is not null);"
        self.assertEqual(sev(db_access.storage_findings(stmts(sql))), ["medium"])

    def test_policy_limited_to_a_bucket_is_clean(self):
        sql = "create policy p on storage.objects for select to authenticated using (bucket_id = 'pics');"
        self.assertEqual(db_access.storage_findings(stmts(sql)), [])


def fake_jwt(role):
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'HS256'})}.{enc({'role': role, 'iss': 'supabase'})}.{enc('sig-sig-sig')}"


class KeyTests(unittest.TestCase):
    def test_service_role_key_in_a_file_is_critical(self):
        f = db_access.key_findings("web/src/supabase.ts", f"const KEY = '{fake_jwt('service_role')}'")
        self.assertEqual(sev(f), ["critical"])

    def test_anon_key_is_fine(self):
        self.assertEqual(db_access.key_findings("web/src/supabase.ts", f"const KEY = '{fake_jwt('anon')}'"), [])

    def test_privileged_key_behind_a_client_env_prefix(self):
        for name in ("VITE_SUPABASE_SERVICE_ROLE_KEY", "NEXT_PUBLIC_STRIPE_SECRET", "REACT_APP_ADMIN_PRIVATE_KEY"):
            f = db_access.key_findings(".env", f"{name}=abc")
            self.assertEqual((sev(f), name in f[0].title), (["high"], True), name)

    def test_publishable_client_vars_are_fine(self):
        self.assertEqual(db_access.key_findings(".env", "VITE_SUPABASE_ANON_KEY=abc\nVITE_API_URL=http://x"), [])

    def test_end_to_end_over_a_temp_project(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "supabase").mkdir()
            (Path(d) / "supabase" / "1.sql").write_text(
                "create view v as select 1; create function f() returns int language sql security definer as $$ select 1 $$;")
            (Path(d) / "app.ts").write_text("const k = import.meta.env.VITE_SERVICE_ROLE_KEY")
            found = db_access.run(Config(source_dir=d), None)
            self.assertEqual(len(found), 4)  # view, definer search_path, public execute, client env key
            self.assertEqual(sorted(set(f.check for f in found)), ["db_access"])

    def test_no_relevant_files_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(Skipped) as cm:
            db_access.run(Config(source_dir=d), None)
        self.assertFalse(cm.exception.applicable)


# ---- E: setup safety ----------------------------------------------------------------------------------------------
class SetupSafetyTests(unittest.TestCase):
    def cli_in(self, cfg_dict, argv):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                Path("guard.config.json").write_text(json.dumps(cfg_dict))
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = cli.main(argv)
                return code, out.getvalue(), err.getvalue()
            finally:
                os.chdir(old)

    def test_fresh_init_config_refuses_live_scans_and_sends_nothing(self):
        sent = []
        real = cli.ScopedHTTP
        cli.ScopedHTTP = lambda *a, **k: sent.append(1)  # would be constructed only for a live scan
        try:
            code, _, err = self.cli_in(DEFAULT_CONFIG, ["scan"])
        finally:
            cli.ScopedHTTP = real
        self.assertEqual((code, sent), (3, []))
        self.assertIn("LIVE SCAN REFUSED", err)
        self.assertIn("setup_complete", err)

    def test_placeholder_host_is_refused_even_when_marked_complete(self):
        code, _, err = self.cli_in({**DEFAULT_CONFIG, "setup_complete": True}, ["scan"])
        self.assertEqual(code, 3)
        self.assertIn("placeholder", err)

    def test_code_only_scan_works_on_a_fresh_config(self):
        code, out, _ = self.cli_in(DEFAULT_CONFIG, ["scan", "--no-live", "--allow-partial"])
        self.assertIn(code, (0, 1))
        self.assertIn("finding", out)

    def test_offline_only_selection_is_not_blocked(self):
        code, _, err = self.cli_in(DEFAULT_CONFIG, ["scan", "--only", "db_rules"])
        self.assertNotEqual(code, 3, err)

    def test_older_configs_without_the_key_keep_working(self):
        self.assertTrue(Config(base_url="https://staging.acme.dev").setup_complete)
        self.assertEqual(Config(base_url="https://staging.acme.dev").live_blocker(), "")

    def test_init_writes_the_flag_off(self):
        self.assertFalse(DEFAULT_CONFIG["setup_complete"])

    def test_init_explains_the_next_step(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    cli.main(["init"])
                self.assertIn("setup_complete", out.getvalue())
                self.assertFalse(json.loads(Path("guard.config.json").read_text())["setup_complete"])
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
