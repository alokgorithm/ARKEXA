import io
import json
import unittest
from contextlib import redirect_stdout

from support import FIXTURES, ROOT

from arkexa import config as config_module
from arkexa.cli import main
from arkexa.engine import scan


def run(argv) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


class ExitCodeTest(unittest.TestCase):
    def test_findings_exit_one(self):
        code, _ = run([str(FIXTURES / "ark001_vulnerable.yml")])
        self.assertEqual(code, 1)

    def test_clean_exits_zero(self):
        code, _ = run([str(FIXTURES / "ark001_safe.yml")])
        self.assertEqual(code, 0)

    def test_missing_target_exits_two(self):
        code, _ = run([str(ROOT / "does-not-exist")])
        self.assertEqual(code, 2)

    def test_severity_threshold_controls_the_exit_code(self):
        """High findings should not fail a build set to critical only."""
        code, _ = run([str(FIXTURES / "ark005_vulnerable.yml"), "--severity", "critical"])
        self.assertEqual(code, 0)


class ReachabilityFilterTest(unittest.TestCase):
    def test_guarded_findings_are_hidden_by_default(self):
        code, output = run([str(FIXTURES / "guarded.yml")])
        self.assertEqual(code, 0)
        self.assertIn("clean", output)

    def test_reachability_all_shows_them(self):
        code, output = run([str(FIXTURES / "guarded.yml"), "--reachability", "all"])
        self.assertEqual(code, 1)
        self.assertIn("ARK001", output)
        self.assertIn("maintainer", output)


class OutputTest(unittest.TestCase):
    def test_json_is_valid_and_carries_the_path(self):
        _, output = run([str(FIXTURES / "ark001_vulnerable.yml"), "--format", "json"])
        payload = json.loads(output)
        self.assertEqual(payload["tool"], "arkexa")
        finding = payload["findings"][0]
        self.assertEqual(finding["rule"], "ARK001")
        self.assertGreaterEqual(len(finding["path"]), 2)
        self.assertTrue(finding["reachable_by"])

    def test_text_output_prints_a_chain_not_a_line_number(self):
        _, output = run([str(FIXTURES / "ark001_vulnerable.yml")])
        self.assertIn("an outsider opens an issue", output)
        self.assertIn("-> env.BODY", output)
        self.assertIn("fix:", output)

    def test_only_filters_rules(self):
        _, output = run([str(FIXTURES / "ark001_vulnerable.yml"), "--only", "ARK002"])
        self.assertNotIn("ARK001", output)

    def test_explain_prints_the_rule(self):
        code, output = run(["--explain", "ARK001"])
        self.assertEqual(code, 0)
        self.assertIn("untrusted-prompt-write-token", output)

    def test_explain_rejects_an_unknown_rule(self):
        code, _ = run(["--explain", "ARK999"])
        self.assertEqual(code, 2)

    def test_list_rules(self):
        code, output = run(["--list-rules"])
        self.assertEqual(code, 0)
        for rule in ("ARK001", "ARK002", "ARK003", "ARK004", "ARK005"):
            self.assertIn(rule, output)


class ConfigTest(unittest.TestCase):
    def test_an_ignore_without_a_reason_is_not_applied(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github" / "workflows").mkdir(parents=True)
            source = (FIXTURES / "ark001_vulnerable.yml").read_text()
            (root / ".github" / "workflows" / "t.yml").write_text(source)

            (root / ".arkexa.yml").write_text("ignore:\n  - rule: ARK001\n")
            configuration = config_module.load(root)
            result = scan(root, config=configuration)
            self.assertTrue(configuration.problems)
            self.assertTrue(result.findings)

            (root / ".arkexa.yml").write_text(
                "ignore:\n  - rule: ARK001\n    reason: tracked in issue 12\n"
            )
            configuration = config_module.load(root)
            result = scan(root, config=configuration)
            self.assertEqual(configuration.problems, [])
            self.assertEqual([f.rule for f in result.findings if f.rule == "ARK001"], [])
            self.assertEqual(result.suppressed, 1)


class FixtureHealthTest(unittest.TestCase):
    def test_every_fixture_parses(self):
        for path in sorted(FIXTURES.glob("*.yml")):
            with self.subTest(fixture=path.name):
                self.assertEqual(scan(path).errors, [])


if __name__ == "__main__":
    unittest.main()
