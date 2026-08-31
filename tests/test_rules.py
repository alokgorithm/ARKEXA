"""Every rule fires on its vulnerable fixture and stays silent on the safe one.

The safe half matters more. False positives are the only thing that can kill
this project, so a rule without a passing safe fixture is not finished.
"""

import unittest

from support import rule_ids, scan_fixture

RULES = ["ARK001", "ARK002", "ARK003", "ARK004", "ARK005"]


class VulnerableFixtureTest(unittest.TestCase):
    def test_each_rule_fires(self):
        for rule in RULES:
            with self.subTest(rule=rule):
                found = rule_ids(scan_fixture(f"{rule.lower()}_vulnerable.yml"))
                self.assertIn(rule, found)


class SafeFixtureTest(unittest.TestCase):
    def test_each_rule_stays_silent(self):
        for rule in RULES:
            with self.subTest(rule=rule):
                found = rule_ids(scan_fixture(f"{rule.lower()}_safe.yml"))
                self.assertNotIn(rule, found)

    def test_safe_fixtures_are_completely_clean(self):
        """A safe fixture should not trip any other rule either."""
        for rule in RULES:
            with self.subTest(rule=rule):
                findings = scan_fixture(f"{rule.lower()}_safe.yml")
                self.assertEqual(
                    findings, [], f"{rule} safe fixture reported {rule_ids(findings)}"
                )


class ReachabilityTest(unittest.TestCase):
    def test_guarded_workflow_is_not_external(self):
        findings = scan_fixture("guarded.yml")
        self.assertTrue(findings, "the guarded fixture should still be detected")
        self.assertTrue(all(f.reachability != "external" for f in findings))
        self.assertTrue(all(f.guards for f in findings))

    def test_dispatch_only_workflow_is_unreachable(self):
        findings = scan_fixture("unreachable.yml")
        for finding in findings:
            self.assertEqual(finding.reachability, "unreachable")

    def test_two_hop_taint_is_reported(self):
        findings = scan_fixture("two_hop.yml")
        self.assertIn("ARK001", rule_ids(findings))
        chain = " ".join(hop.text for hop in findings[0].hops)
        self.assertIn("env.TITLE", chain)


class ExploitPathTest(unittest.TestCase):
    def test_a_finding_always_carries_a_path(self):
        for rule in RULES:
            with self.subTest(rule=rule):
                for finding in scan_fixture(f"{rule.lower()}_vulnerable.yml"):
                    self.assertTrue(finding.hops, "a finding must show its chain")
                    self.assertTrue(finding.opening)
                    self.assertTrue(finding.fix)
                    self.assertTrue(finding.impact)
                    self.assertTrue(all(hop.line > 0 for hop in finding.hops))


if __name__ == "__main__":
    unittest.main()
