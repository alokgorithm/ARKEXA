"""ARK001 - untrusted text reaches an agent prompt in a job holding write."""

from __future__ import annotations

from typing import Iterator

from ..registry import Context, Finding, rule
from ..taint import UNTRUSTED, Hop

EXPLANATION = """
An agent step reads text an outsider wrote, and the job it runs in holds a
write scope on the GITHUB_TOKEN. The model cannot tell the difference between
the text you meant as data and the instructions inside it, so whatever the
outsider wrote is instruction-adjacent to a token that can change your
repository.

This is the whole reason ARKEXA exists. Everything else in the catalog is a
variation on it.

Fixes, best first:

  1. Do not put untrusted text in the prompt. Write it to a file and tell the
     agent to treat the file as data.
  2. Drop the job to `permissions: contents: read` and let a second,
     unprivileged job do any writing from a reviewed artifact.
  3. Gate the job on `author_association`, which demotes the finding to
     `contributor` or `maintainer` rather than removing it.
"""


@rule(
    id="ARK001",
    name="untrusted-prompt-write-token",
    severity="critical",
    owasp="ASI01 Agent Instruction Injection",
    summary="Untrusted event data reaches an agent prompt in a job holding a write scope",
    explanation=EXPLANATION,
)
def check(context: Context) -> Iterator[Finding]:
    permissions = context.job.permissions
    if permissions.declared and not permissions.write_scopes:
        return

    permission_line = permissions.line or context.job.line
    permission_file = permissions.file
    scope_text = f"job '{context.job.id}' {permissions.describe()}"

    for agent in context.agents:
        reported: set[str] = set()

        for surface in agent.prompts:
            taints = context.taint.of_value(
                agent.step, surface.text, surface.line, shell=surface.shell
            )
            for taint in taints:
                if taint.kind != UNTRUSTED or taint.source_path in reported:
                    continue
                reported.add(taint.source_path)
                destination = f"{surface.where} of {agent.label}"
                final = taint.hop_to(destination, surface.line)
                hops = [*final.hops, Hop(scope_text, permission_line, file=permission_file)]
                yield context.finding(
                    line=surface.line,
                    hops=hops,
                    impact=(
                        "text an outsider controls is instruction-adjacent to an agent "
                        "that can write to your repository"
                    ),
                    fix=(
                        "pass untrusted text as a file the agent reads as data, drop the "
                        "job to read-only permissions, or gate the job on author_association"
                    ),
                    opening=taint.phrase,
                )

        if agent.implicit_event and not reported:
            external_events = [
                event
                for event in context.workflow.triggers
                if event
                in {
                    "issues",
                    "issue_comment",
                    "pull_request",
                    "pull_request_target",
                    "pull_request_review",
                    "pull_request_review_comment",
                    "discussion",
                    "discussion_comment",
                }
            ]
            if not external_events:
                continue
            event = external_events[0]
            hops = [
                Hop(
                    f"{event} payload -> {agent.name} reads the triggering text by design",
                    agent.step.line,
                ),
                Hop(scope_text, permission_line, file=permission_file),
            ]
            yield context.finding(
                line=agent.step.line,
                hops=hops,
                impact=(
                    "the action ingests the triggering text with no prompt of its own, "
                    "so an outsider writes directly into the model's context while the "
                    "job can write to your repository"
                ),
                fix=(
                    "set an explicit prompt that treats the event text as data, or drop "
                    "the job to read-only permissions"
                ),
            )
