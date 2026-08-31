import unittest
from pathlib import Path

from support import FIXTURES  # noqa: F401

from arkexa import detect
from arkexa.model import build
from arkexa.taint import MODEL, UNTRUSTED, WorkflowTaint


def tables(text: str):
    flow = build(Path("t.yml"), text)
    agent_ids = detect.agent_step_ids(flow)
    by_id = {
        job_id: {a.step.id: a for a in detect.agents_in_job(job) if a.step.id}
        for job_id, job in flow.jobs.items()
    }
    return flow, WorkflowTaint(flow, agent_ids, by_id)


class EnvPropagationTest(unittest.TestCase):
    def test_job_env_carries_taint_into_a_step(self):
        flow, taint = tables(
            "on: [issues]\n"
            "jobs:\n"
            "  go:\n"
            "    env:\n"
            "      BODY: ${{ github.event.issue.body }}\n"
            "    steps:\n"
            "      - run: claude -p \"$BODY\"\n"
        )
        job = flow.jobs["go"]
        found = taint.for_job(job).of_run(job.steps[0])
        self.assertEqual([t.kind for t in found], [UNTRUSTED])
        self.assertEqual(found[0].tip, "env.BODY")

    def test_untainted_env_stays_quiet(self):
        flow, taint = tables(
            "on: [issues]\n"
            "jobs:\n"
            "  go:\n"
            "    env:\n"
            "      BODY: a fixed string\n"
            "    steps:\n"
            "      - run: claude -p \"$BODY\"\n"
        )
        job = flow.jobs["go"]
        self.assertEqual(taint.for_job(job).of_run(job.steps[0]), [])

    def test_github_env_export_reaches_a_later_step(self):
        flow, taint = tables(
            "on: [issues]\n"
            "jobs:\n"
            "  go:\n"
            "    steps:\n"
            "      - run: echo \"T=${{ github.event.issue.title }}\" >> \"$GITHUB_ENV\"\n"
            "      - run: claude -p \"$T\"\n"
        )
        job = flow.jobs["go"]
        found = taint.for_job(job).of_run(job.steps[1])
        self.assertEqual([t.kind for t in found], [UNTRUSTED])


class ModelTaintTest(unittest.TestCase):
    SOURCE = (
        "on: [issues]\n"
        "jobs:\n"
        "  go:\n"
        "    steps:\n"
        "      - id: ai\n"
        "        uses: actions/ai-inference@v1\n"
        "        with:\n"
        "          prompt: ${{ github.event.issue.body }}\n"
        "      - run: echo \"${{ steps.ai.outputs.response }}\"\n"
    )

    def test_agent_output_is_model_tainted(self):
        flow, taint = tables(self.SOURCE)
        job = flow.jobs["go"]
        found = taint.for_job(job).of_run(job.steps[1])
        self.assertEqual([t.kind for t in found], [MODEL])

    def test_model_output_keeps_the_provenance_of_its_prompt(self):
        """The chain has to read from the issue body, not from the model."""
        flow, taint = tables(self.SOURCE)
        job = flow.jobs["go"]
        found = taint.for_job(job).of_run(job.steps[1])
        chain = " | ".join(hop.text for hop in found[0].hops)
        self.assertIn("github.event.issue.body", chain)
        self.assertIn("the model answers", chain)
        self.assertEqual(found[0].phrase, "an outsider opens an issue")


class CrossJobTest(unittest.TestCase):
    def test_needs_outputs_carry_taint(self):
        flow, taint = tables(
            "on: [issues]\n"
            "jobs:\n"
            "  first:\n"
            "    outputs:\n"
            "      body: ${{ steps.grab.outputs.body }}\n"
            "    steps:\n"
            "      - id: grab\n"
            "        run: echo \"body=${{ github.event.issue.body }}\" >> \"$GITHUB_OUTPUT\"\n"
            "  second:\n"
            "    needs: first\n"
            "    steps:\n"
            "      - run: claude -p \"${{ needs.first.outputs.body }}\"\n"
        )
        job = flow.jobs["second"]
        found = taint.for_job(job).of_run(job.steps[0])
        self.assertEqual([t.kind for t in found], [UNTRUSTED])


if __name__ == "__main__":
    unittest.main()
