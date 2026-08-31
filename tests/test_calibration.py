"""Regressions found by running ARKEXA on real third-party workflows.

Every test here corresponds to something the tool got wrong on a workflow
nobody wrote for it. Fixtures prove a rule works; these prove it works on
code written by people who had never heard of ARKEXA, which is the only
evidence that means anything about precision.

No repository is named. See SECURITY.md.
"""

import tempfile
import unittest
from pathlib import Path

from support import FIXTURES  # noqa: F401

from arkexa.engine import scan


def findings(text: str):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "w.yml"
        path.write_text(text, encoding="utf-8")
        return scan(path).findings


def external(text: str):
    return [f for f in findings(text) if f.reachability == "external"]


class SubpathActionTest(unittest.TestCase):
    """A subpath action is not its parent.

    `claude-code-action/base-action` runs the prompt it is handed. It does not
    read the triggering issue by itself, so the implicit-event finding that
    applies to the parent action must not fire for it.
    """

    BASE = """
on:
  issues:
    types: [opened]
jobs:
  go:
    permissions:
      issues: write
    steps:
      - uses: anthropics/claude-code-action/base-action@v1
        with:
          prompt: "/dedupe issue ${{ github.event.issue.number }}"
"""

    def test_base_action_with_a_safe_prompt_is_quiet(self):
        self.assertEqual(findings(self.BASE), [])

    def test_the_parent_action_is_still_detected(self):
        parent = self.BASE.replace("claude-code-action/base-action", "claude-code-action")
        self.assertTrue(findings(parent))


class BuiltinGuardTest(unittest.TestCase):
    """The action checks its caller, and ARKEXA cannot see that from the file.

    claude-code-action refuses to run for callers without write access. A
    scanner that ignores this calls the most common agentic workflow in the
    world externally reachable, which is wrong and is how a tool loses trust.
    """

    GUARDED = """
on:
  issue_comment:
    types: [created]
jobs:
  go:
    permissions:
      contents: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: "--model opus"
"""

    def test_the_builtin_check_demotes_the_finding(self):
        found = findings(self.GUARDED)
        self.assertTrue(found, "the path is still real, it is just not external")
        self.assertTrue(all(f.reachability == "maintainer" for f in found))
        self.assertEqual(external(self.GUARDED), [])

    def test_the_demotion_is_explained_not_hidden(self):
        note = " ".join(name for f in findings(self.GUARDED) for name, _, _ in f.guards)
        self.assertIn("write access", note)

    def test_bypassing_the_check_makes_it_external_again(self):
        bypassed = self.GUARDED.replace(
            'claude_args: "--model opus"',
            "allowed_non_write_users: '*'",
        )
        self.assertTrue(external(bypassed))


class ActorAllowlistTest(unittest.TestCase):
    """Workflows name the caller on the event payload, not just github.actor."""

    def workflow(self, condition: str) -> str:
        return f"""
on:
  issue_comment:
    types: [created]
jobs:
  go:
    if: {condition}
    permissions:
      contents: write
    steps:
      - run: claude -p "review ${{{{ github.event.comment.body }}}}"
"""

    def test_login_allowlist_is_a_guard(self):
        self.assertEqual(external(self.workflow("github.event.comment.user.login == 'ada'")), [])

    def test_repository_check_is_a_guard(self):
        self.assertEqual(external(self.workflow("github.repository == 'owner/repo'")), [])

    def test_an_unguarded_workflow_is_still_reported(self):
        self.assertTrue(external(self.workflow("github.event.issue.pull_request")))

    def test_a_negated_login_check_is_not_a_guard(self):
        self.assertTrue(external(self.workflow("github.event.comment.user.login != 'bot'")))


class AuthorizeJobTest(unittest.TestCase):
    """Gating on the output of an authorisation job is a guard.

    Real workflows put the permission check in its own job and gate on its
    output far more often than they write author_association into an `if:`.
    """

    SOURCE = """
on:
  pull_request_target:
    # `opened` is the externally reachable half. Without the authorisation gate
    # below, a stranger opening a pull request reaches the agent.
    types: [opened, labeled]
jobs:
  authorize:
    outputs:
      ok: ${{ steps.check.outputs.ok }}
    steps:
      - id: check
        run: |
          if [[ "${{ contains(github.event.pull_request.labels.*.name, 'approved') }}" == "true" ]]; then
            echo "ok=true" >> $GITHUB_OUTPUT
          fi
  fix:
    needs: authorize
    if: needs.authorize.outputs.ok == 'true'
    permissions:
      contents: write
    steps:
      - run: aider --yes --message "fix ${{ github.event.pull_request.title }}"
"""

    def test_the_gate_is_recognised(self):
        self.assertEqual(external(self.SOURCE), [])

    def test_without_the_gate_it_is_external(self):
        ungated = self.SOURCE.replace("if: needs.authorize.outputs.ok == 'true'", "")
        self.assertTrue(external(ungated))


class PushRefspecTest(unittest.TestCase):
    """`git push origin HEAD:$BRANCH` is not a push to the default branch."""

    def workflow(self, push: str) -> str:
        return f"""
on: [issues]
jobs:
  go:
    permissions:
      contents: write
    steps:
      - run: claude -p "fix it"
      - run: |
          {push}
"""

    def test_pushing_to_a_variable_branch_is_not_reported(self):
        found = self.workflow('git push "https://x@github.com/o/r.git" HEAD:"$HEAD_BRANCH"')
        self.assertNotIn("ARK005", {f.rule for f in findings(found)})

    def test_pushing_to_main_is_still_reported(self):
        found = self.workflow("git push origin main")
        self.assertIn("ARK005", {f.rule for f in findings(found)})


class ReadOnlyAgentTest(unittest.TestCase):
    """An agent with approvals off and no write scope is noise, not a finding."""

    def workflow(self, permissions: str) -> str:
        return f"""
on: [pull_request]
jobs:
  go:
    permissions:
{permissions}
    steps:
      - run: claude --dangerously-skip-permissions -p "run the fuzzer"
"""

    def test_no_write_scope_is_not_reported(self):
        self.assertNotIn("ARK004", {f.rule for f in findings(self.workflow("      contents: read"))})

    def test_a_write_scope_is_reported(self):
        self.assertIn("ARK004", {f.rule for f in findings(self.workflow("      contents: write"))})


class DeduplicationTest(unittest.TestCase):
    """One prompt is one problem, however many sources reach it."""

    SOURCE = """
on:
  issues:
    types: [opened]
jobs:
  go:
    permissions:
      issues: write
    steps:
      - uses: actions/ai-inference@v1
        with:
          prompt: |
            Title: ${{ github.event.issue.title }}
            Body: ${{ github.event.issue.body }}
"""

    def test_one_finding_for_one_prompt(self):
        found = [f for f in findings(self.SOURCE) if f.rule == "ARK001"]
        self.assertEqual(len(found), 1)

    def test_the_other_source_is_still_named(self):
        found = [f for f in findings(self.SOURCE) if f.rule == "ARK001"][0]
        self.assertIn("also reached by", found.impact)


class InvalidWorkflowTest(unittest.TestCase):
    """One workflow in 85 was invalid YAML. Report it, do not crash on it."""

    def test_a_broken_workflow_is_an_error_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "w.yml"
            path.write_text("on: [push]\njobs:\n  a:\n    steps:\n      - name: x: y\n")
            result = scan(path)
            self.assertTrue(result.errors)
            self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
