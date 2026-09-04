"""SARIF is what GitHub reads, so its shape is a contract, not a detail.

A malformed field does not raise: code scanning accepts the upload and then
shows nothing, or shows every alert at "unknown severity" at the bottom of the
Security tab. These tests pin the fields that decide whether a finding is
visible and whether it stays the same alert across runs.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path

from support import FIXTURES  # noqa: F401

from arkexa import render
from arkexa.engine import scan

VULNERABLE = """
on:
  issues:
    types: [opened]
jobs:
  triage:
    permissions:
      issues: write
    steps:
      - uses: actions/ai-inference@v1
        with:
          prompt: "Summarise ${{ github.event.issue.title }}"
"""


def sarif(text: str) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "w.yml"
        path.write_text(text, encoding="utf-8")
        result = scan(path)
        stream = io.StringIO()
        render.render_sarif(result, stream)
        return json.loads(stream.getvalue())


class ShapeTest(unittest.TestCase):
    def setUp(self):
        self.doc = sarif(VULNERABLE)
        self.run = self.doc["runs"][0]

    def test_it_is_valid_json_at_the_declared_version(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0", self.doc["$schema"])

    def test_the_driver_names_the_tool_and_its_version(self):
        driver = self.run["tool"]["driver"]
        self.assertEqual(driver["name"], "ARKEXA")
        self.assertTrue(driver["version"])
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_a_finding_becomes_a_result(self):
        self.assertTrue(self.run["results"])
        first = self.run["results"][0]
        self.assertEqual(first["ruleId"], "ARK001")
        self.assertEqual(first["level"], "error")

    def test_every_result_points_at_a_rule_that_is_declared(self):
        declared = [rule["id"] for rule in self.run["tool"]["driver"]["rules"]]
        for result in self.run["results"]:
            self.assertIn(result["ruleId"], declared)
            self.assertEqual(declared[result["ruleIndex"]], result["ruleId"])

    def test_locations_carry_a_file_and_a_line(self):
        location = self.run["results"][0]["locations"][0]["physicalLocation"]
        self.assertTrue(location["artifactLocation"]["uri"])
        self.assertGreaterEqual(location["region"]["startLine"], 1)

    def test_the_exploit_path_survives_as_related_locations(self):
        """The chain is the finding. Flattening it into prose loses the point."""
        related = self.run["results"][0]["relatedLocations"]
        self.assertGreaterEqual(len(related), 2)
        for step in related:
            self.assertTrue(step["message"]["text"])
            self.assertGreaterEqual(
                step["physicalLocation"]["region"]["startLine"], 1
            )

    def test_security_severity_is_set_so_github_can_sort(self):
        """Without this every alert lands at the bottom as unknown severity."""
        for rule in self.run["tool"]["driver"]["rules"]:
            severity = rule["properties"]["security-severity"]
            self.assertTrue(0.0 <= float(severity) <= 10.0)

    def test_rules_carry_help_text_a_maintainer_can_act_on(self):
        for rule in self.run["tool"]["driver"]["rules"]:
            self.assertTrue(rule["help"]["text"])
            self.assertTrue(rule["shortDescription"]["text"])


class FingerprintTest(unittest.TestCase):
    """An alert that changes identity reopens itself on every run."""

    def test_the_same_workflow_fingerprints_the_same(self):
        first = sarif(VULNERABLE)["runs"][0]["results"][0]
        second = sarif(VULNERABLE)["runs"][0]["results"][0]
        self.assertEqual(first["partialFingerprints"], second["partialFingerprints"])

    def test_moving_a_line_does_not_change_the_fingerprint(self):
        before = sarif(VULNERABLE)["runs"][0]["results"][0]
        after = sarif("\n# a new comment line\n" + VULNERABLE)["runs"][0]["results"][0]
        self.assertNotEqual(
            before["locations"][0]["physicalLocation"]["region"]["startLine"],
            after["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        self.assertEqual(before["partialFingerprints"], after["partialFingerprints"])

    def test_a_different_finding_fingerprints_differently(self):
        other = VULNERABLE.replace("triage", "review")
        self.assertNotEqual(
            sarif(VULNERABLE)["runs"][0]["results"][0]["partialFingerprints"],
            sarif(other)["runs"][0]["results"][0]["partialFingerprints"],
        )


class QuietTest(unittest.TestCase):
    def test_a_clean_workflow_produces_a_valid_empty_run(self):
        """Uploading nothing must still be a valid document, or the step fails."""
        doc = sarif("on: [push]\njobs:\n  a:\n    steps:\n      - run: echo hi\n")
        run = doc["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])


class CliTest(unittest.TestCase):
    def test_the_format_is_offered_and_produces_sarif(self):
        """Through the real CLI, because that is how the Action invokes it."""
        import contextlib

        from arkexa.cli import main

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "w.yml"
            path.write_text(VULNERABLE, encoding="utf-8")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                main([str(path), "--format", "sarif"])
        doc = json.loads(captured.getvalue())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_sarif_is_listed_as_a_choice(self):
        from arkexa.cli import build_parser

        action = next(
            a for a in build_parser()._actions if "--format" in getattr(a, "option_strings", [])
        )
        self.assertIn("sarif", action.choices)


if __name__ == "__main__":
    unittest.main()
