import unittest
from pathlib import Path

from support import FIXTURES  # noqa: F401

from arkexa import reach
from arkexa.model import build


def workflow(text: str):
    return build(Path("t.yml"), text)


class TriggerLevelTest(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(reach._trigger_level("issue_comment"), "external")
        self.assertEqual(reach._trigger_level("pull_request_target"), "external")
        self.assertEqual(reach._trigger_level("push"), "maintainer")
        self.assertEqual(reach._trigger_level("workflow_dispatch"), "unreachable")

    def test_activity_types_can_demote(self):
        """Only someone with triage access can label an issue."""
        self.assertEqual(
            reach._trigger_level("issues", {"types": ["labeled"]}), "maintainer"
        )
        self.assertEqual(
            reach._trigger_level("issues", {"types": ["opened", "labeled"]}), "external"
        )


class GuardTest(unittest.TestCase):
    def test_author_association_demotes_to_maintainer(self):
        guards = reach.detect_guards(
            [("github.event.comment.author_association == 'OWNER'", 3)]
        )
        self.assertEqual([level for _, level, _ in guards], ["maintainer"])

    def test_contributor_allowlist_demotes_further_only(self):
        guards = reach.detect_guards(
            [("contains(fromJSON('[\"OWNER\",\"CONTRIBUTOR\"]'), "
              "github.event.comment.author_association)", 3)]
        )
        self.assertEqual(guards[0][1], "contributor")

    def test_negated_check_is_not_a_guard(self):
        """`github.actor != 'dependabot[bot]'` excludes a bot, not an outsider."""
        self.assertEqual(reach.detect_guards([("github.actor != 'dependabot[bot]'", 3)]), [])

    def test_label_gate_is_a_guard(self):
        guards = reach.detect_guards(
            [("contains(github.event.issue.labels.*.name, 'agent-ok')", 4)]
        )
        self.assertEqual(guards[0][1], "maintainer")


class ClassifyTest(unittest.TestCase):
    def test_guard_on_a_needed_job_is_inherited(self):
        text = (
            "on: [issue_comment]\n"
            "jobs:\n"
            "  gate:\n"
            "    if: github.event.comment.author_association == 'OWNER'\n"
            "    steps: []\n"
            "  work:\n"
            "    needs: gate\n"
            "    steps: []\n"
        )
        flow = workflow(text)
        self.assertEqual(reach.classify(flow, flow.jobs["work"]).level, "maintainer")

    def test_unguarded_external_trigger(self):
        flow = workflow("on: [issues]\njobs:\n  go:\n    steps: []\n")
        result = reach.classify(flow, flow.jobs["go"])
        self.assertEqual(result.level, "external")
        self.assertEqual(result.phrase, "an outsider opens an issue")

    def test_dispatch_only_is_unreachable(self):
        flow = workflow("on:\n  workflow_dispatch:\njobs:\n  go:\n    steps: []\n")
        self.assertEqual(reach.classify(flow, flow.jobs["go"]).level, "unreachable")


if __name__ == "__main__":
    unittest.main()
