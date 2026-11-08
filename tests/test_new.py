import json
import tempfile
import unittest
from pathlib import Path

from guard.checks import ai, cookies, db_rules, exposed, jwt, mass_assignment, upload
from guard.config import Config
from guard.findings import Finding
from guard.loop import decide, record_run, write_fix_tasks, write_summary


def make_token(payload, alg="HS256"):
    h = jwt._b64e(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = jwt._b64e(json.dumps(payload).encode())
    return f"{h}.{p}.sig"


class JwtTests(unittest.TestCase):
    def test_no_exp(self):
        self.assertEqual(jwt.evaluate_token(make_token({"sub": "1"}))[0].title, "Token never expires")

    def test_alg_none(self):
        titles = [f.title for f in jwt.evaluate_token(make_token({"exp": 9999999999}, alg="none"))]
        self.assertIn("Token uses alg=none", titles)

    def test_long_lifetime(self):
        f = jwt.evaluate_token(make_token({"iat": 0, "exp": 90 * 86400}))
        self.assertEqual(f[0].severity, "low")

    def test_forgeries_shape(self):
        labels = [l for l, _ in jwt.forgeries(make_token({"exp": 1}))]
        self.assertEqual(labels, ["alg=none", "signature-stripped", "tampered-payload"])
        none_tok = jwt.forgeries(make_token({"exp": 1}))[0][1]
        self.assertEqual(jwt.decode(none_tok)[0]["alg"], "none")

    def test_garbage_token(self):
        self.assertEqual(jwt.evaluate_token("not-a-jwt"), [])


class MassAssignTests(unittest.TestCase):
    def test_echoed_role(self):
        f = mass_assignment.evaluate("u", 200, json.dumps({"user": {"role": "admin", "name": "x"}}))
        self.assertEqual(f[0].severity, "high")

    def test_ignored_fields(self):
        self.assertEqual(mass_assignment.evaluate("u", 200, json.dumps({"name": "x", "role": "user"})), [])

    def test_error_status(self):
        self.assertEqual(mass_assignment.evaluate("u", 400, json.dumps({"role": "admin"})), [])


class UploadTests(unittest.TestCase):
    def test_accepted_php(self):
        self.assertEqual(upload.evaluate("u", "a.php", 201, "high")[0].severity, "high")

    def test_rejected(self):
        self.assertEqual(upload.evaluate("u", "a.php", 415, "high"), [])

    def test_multipart(self):
        body, ctype = upload.build_multipart("file", "a.txt", "text/plain", b"hi")
        self.assertIn(b'filename="a.txt"', body)
        self.assertIn("boundary=", ctype)


class DbRulesTests(unittest.TestCase):
    def test_table_without_rls(self):
        f = db_rules.evaluate_sql("m.sql", "create table public.notes (id int);", high=True)
        self.assertEqual((f[0].severity, "notes" in f[0].title), ("high", True))

    def test_table_with_rls(self):
        sql = "create table notes (id int);\nalter table notes enable row level security;"
        self.assertEqual(db_rules.evaluate_sql("m.sql", sql, high=False), [])

    def test_open_policy(self):
        sql = ("create table t (id int); alter table t enable row level security;\n"
               "create policy \"all\" on t for select using (true);")
        f = db_rules.evaluate_sql("m.sql", sql, high=False)
        self.assertEqual(f[0].severity, "high")

    def test_commented_out_table_ignored(self):
        self.assertEqual(db_rules.evaluate_sql("m.sql", "-- create table x (id int);", high=False), [])


class ExposedTests(unittest.TestCase):
    def test_real_env(self):
        self.assertEqual(exposed.evaluate("/.env", "u", 200, "DB_PASSWORD=hunter2")[0].severity, "critical")

    def test_spa_catchall_not_flagged(self):
        self.assertEqual(exposed.evaluate("/.env", "u", 200, "<!doctype html><html></html>"), [])

    def test_git_head(self):
        self.assertEqual(len(exposed.evaluate("/.git/HEAD", "u", 200, "ref: refs/heads/main")), 1)


class CookieTests(unittest.TestCase):
    def test_weak_session_cookie(self):
        f = cookies.evaluate("https://x", ["session=abc; Path=/"])
        titles = [x.title for x in f]
        self.assertIn("Cookie 'session' missing HttpOnly", titles)
        self.assertIn("Cookie 'session' missing Secure", titles)

    def test_good_cookie(self):
        self.assertEqual(cookies.evaluate("https://x", ["session=a; Secure; HttpOnly; SameSite=Lax"]), [])

    def test_http_skips_secure(self):
        titles = [x.title for x in cookies.evaluate("http://localhost", ["sid=a; HttpOnly; SameSite=Lax"])]
        self.assertEqual(titles, [])


class AiTests(unittest.TestCase):
    def test_client_exposed_key(self):
        self.assertEqual(ai.evaluate_static("a.env", "NEXT_PUBLIC_OPENAI_API_KEY=abc")[0].severity, "high")

    def test_eval_model_output(self):
        f = ai.evaluate_static("a.py", "result = eval(llm_response)")
        self.assertEqual(f[0].severity, "medium")

    def test_raw_html_model_output(self):
        f = ai.evaluate_static("a.tsx", "<div dangerouslySetInnerHTML={{__html: completion}} />")
        self.assertEqual(f[0].severity, "medium")

    def test_clean_code(self):
        self.assertEqual(ai.evaluate_static("a.py", "print('hello')"), [])

    def test_canary_leak(self):
        self.assertEqual(ai.evaluate_probe("u", "p", "the code is CANARY-123", ["CANARY-123"])[0].severity, "high")

    def test_no_leak(self):
        self.assertEqual(ai.evaluate_probe("u", "p", "I cannot help", ["CANARY-123"]), [])


class ConfigTests(unittest.TestCase):
    def test_defaults_construct(self):
        self.assertEqual(Config().max_fix_rounds, 5)


class DecideTests(unittest.TestCase):
    def test_blocking_sends_back(self):
        self.assertEqual(decide(2, {}, 5, True), (2, "fix", {"attempts": 1}))

    def test_attempts_increment(self):
        self.assertEqual(decide(1, {"attempts": 2}, 5, True)[2], {"attempts": 3})

    def test_gives_up_then_allows_stop(self):
        code, kind, state = decide(1, {"attempts": 5}, 5, True)
        self.assertEqual((code, kind), (2, "gave_up"))
        self.assertEqual(decide(1, state, 5, True)[0], 0)

    def test_clean_after_fixes_requests_summary_once(self):
        code, kind, state = decide(0, {"attempts": 2}, 5, True)
        self.assertEqual((code, kind), (2, "summary"))
        self.assertEqual(decide(0, state, 5, True)[:2], (0, "done"))

    def test_gave_up_stays_quiet_while_issues_remain(self):
        self.assertEqual(decide(1, {"gave_up": True}, 5, True), (0, "done", {"gave_up": True}))
        self.assertEqual(decide(0, {"gave_up": True}, 5, True), (0, "done", {}))

    def test_clean_from_start_is_silent(self):
        self.assertEqual(decide(0, {}, 5, False)[:2], (0, "done"))


class LoopTests(unittest.TestCase):
    def test_fix_cycle_tracking(self):
        high = Finding("db_rules", "high", "Table 'a' has no row-level security", "d", "m.sql", fix="enable rls")
        low = Finding("headers", "low", "Missing referrer-policy", "d", "u")
        with tempfile.TemporaryDirectory() as d:
            r1 = record_run(d, [high, low], "high")
            self.assertFalse(r1["clean"])
            self.assertEqual((len(r1["blocking"]), r1["rounds"]), (1, 1))
            self.assertIn("suggested fix: enable rls", write_fix_tasks(d, r1).read_text())
            r2 = record_run(d, [low], "high")  # high issue fixed
            self.assertTrue(r2["clean"])
            self.assertEqual([x["title"] for x in r2["fixed"]], [high.title])
            text = write_summary(d, r2, "high").read_text()
            self.assertIn("CLEAN", text)
            self.assertIn("Fixed (1)", text)
            r3 = record_run(d, [], "high")  # new session after a clean one
            self.assertEqual((r3["rounds"], r3["seen_total"]), (1, 0))

    def test_nonblocking_only_never_needs_summary(self):
        low = Finding("headers", "low", "Missing referrer-policy", "d", "u")
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(record_run(d, [low], "high")["had_blocking"])
            self.assertTrue(record_run(d, [Finding("c", "high", "t", "d", "x")], "high")["had_blocking"])

    def test_info_findings_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            r = record_run(d, [Finding("x", "info", "skipped", "d")], "high")
            self.assertEqual(r["seen_total"], 0)


if __name__ == "__main__":
    unittest.main()
