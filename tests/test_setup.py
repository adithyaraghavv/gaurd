import json
import tempfile
import unittest
from pathlib import Path

from guard.assets import HOOK_COMMAND, RULES_START
from guard.claude_setup import add_hook, add_rules, ensure_gitignore, install
from guard.cli import main


class SetupTests(unittest.TestCase):
    def test_installs_command_and_rules(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            out = install(claude, claude / "CLAUDE.md")
            self.assertTrue((claude / "commands" / "guard.md").exists())
            self.assertIn("guard scan --no-live", (claude / "commands" / "guard.md").read_text())
            self.assertIn(RULES_START, (claude / "CLAUDE.md").read_text())
            self.assertEqual(len(out), 2)

    def test_hook_is_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            install(claude, claude / "CLAUDE.md")
            self.assertFalse((claude / "settings.json").exists())
            install(claude, claude / "CLAUDE.md", hook=True)
            data = json.loads((claude / "settings.json").read_text())
            self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"], HOOK_COMMAND)

    def test_hook_merge_keeps_existing_settings(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            p.write_text(json.dumps({"model": "x", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "other"}]}],
                                                              "PreToolUse": [{"matcher": "Bash", "hooks": []}]}}))
            add_hook(p)
            data = json.loads(p.read_text())
            self.assertEqual(data["model"], "x")
            self.assertIn("PreToolUse", data["hooks"])
            self.assertEqual(len(data["hooks"]["Stop"]), 2)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            for _ in range(3):
                install(claude, claude / "CLAUDE.md", hook=True)
            self.assertEqual(len(json.loads((claude / "settings.json").read_text())["hooks"]["Stop"]), 1)
            self.assertEqual((claude / "CLAUDE.md").read_text().count(RULES_START), 1)

    def test_rules_append_keeps_user_content(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "CLAUDE.md"
            p.write_text("# My notes\nkeep me\n")
            add_rules(p)
            text = p.read_text()
            self.assertTrue(text.startswith("# My notes\nkeep me"))
            self.assertIn(RULES_START, text)

    def test_invalid_settings_json_not_clobbered(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            p.write_text("{ not json")
            self.assertIn("not valid JSON", add_hook(p))
            self.assertEqual(p.read_text(), "{ not json")

    def test_repo_adds_self_install_steps(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            install(claude, claude / "CLAUDE.md", repo="adithyaraghavv/gaurd")
            text = (claude / "commands" / "guard.md").read_text()
            self.assertIn("git clone --depth 1 https://github.com/adithyaraghavv/gaurd", text)
            self.assertIn("add_repo", text)

    def test_without_repo_no_clone_step(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            install(claude, claude / "CLAUDE.md")
            self.assertNotIn("git clone", (claude / "commands" / "guard.md").read_text())

    def test_bad_repo_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                install(Path(d) / ".claude", Path(d) / "CLAUDE.md", repo="bad repo; rm -rf /")
            self.assertEqual(main(["setup", "--home", d, "--repo", "not valid"]), 2)

    def test_gitignore_idempotent_and_preserves(self):
        with tempfile.TemporaryDirectory() as d:
            g = Path(d) / ".gitignore"
            g.write_text("node_modules/")
            ensure_gitignore(g)
            ensure_gitignore(g)
            lines = g.read_text().splitlines()
            self.assertEqual(lines, ["node_modules/", "guard_out/", "guard.config.json"])

    def test_cli_setup_with_home(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["setup", "--home", d, "--hook"]), 0)
            self.assertTrue((Path(d) / ".claude" / "commands" / "guard.md").exists())
            self.assertTrue((Path(d) / ".claude" / "settings.json").exists())


if __name__ == "__main__":
    unittest.main()
