"""Following a local composite action one level down.

Most scanners stop at the top-level workflow file, so a dangerous step wrapped
in a local action is invisible to them. This is the case that proves ARKEXA
does not stop there, and that the chain still names the file it crosses into.
"""

import unittest

from support import FIXTURES

from arkexa.engine import scan

REPO = FIXTURES / "repo"


class CompositeTest(unittest.TestCase):
    def setUp(self):
        self.findings = scan(REPO).findings

    def test_a_finding_inside_the_action_is_reported(self):
        self.assertEqual([f.rule for f in self.findings], ["ARK001"])

    def test_the_finding_is_attributed_to_the_action_file(self):
        self.assertTrue(self.findings[0].workflow.endswith("summarise/action.yml"))

    def test_the_chain_crosses_the_file_boundary(self):
        finding = self.findings[0]
        files = {hop.file for hop in finding.hops if hop.file}
        self.assertIn(".github/workflows/main.yml", files)
        chain = " | ".join(hop.text for hop in finding.hops)
        self.assertIn("calls ./.github/actions/summarise", chain)

    def test_the_action_input_carries_the_provenance_of_the_caller(self):
        """`inputs.body` on its own means nothing; what the caller passed does."""
        chain = " | ".join(hop.text for hop in self.findings[0].hops)
        self.assertIn("github.event.issue.body -> inputs.body", chain)
        self.assertIn("inputs.body -> env.TEXT", chain)

    def test_permissions_come_from_the_calling_job(self):
        chain = " | ".join(hop.text for hop in self.findings[0].hops)
        self.assertIn("contents: write", chain)

    def test_the_trigger_is_read_from_the_caller(self):
        finding = self.findings[0]
        self.assertEqual(finding.reachability, "external")
        self.assertEqual(finding.opening_file, ".github/workflows/main.yml")

    def test_no_follow_turns_it_off(self):
        self.assertEqual(scan(REPO, follow_local=False).findings, [])


if __name__ == "__main__":
    unittest.main()
