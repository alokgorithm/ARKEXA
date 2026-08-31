"""ARK005 - an agent job pushes to the default branch or force-merges."""

from __future__ import annotations

import re
from typing import Iterator

from ..registry import Context, Finding, rule
from ..taint import Hop

EXPLANATION = """
A job that runs an agent also pushes straight to the default branch, or merges
a pull request with `--admin`, which skips required reviews. That removes the
last checkpoint: whatever the agent produced is on main without anyone reading
it, and on main it runs in every subsequent workflow.

The safe shape is for the agent to open a pull request. A pull request is the
review gate, and it costs nothing to keep.

Fix: push to a branch and open a pull request, drop `--admin`, and let a human
or a required check merge.
"""

# `git push origin HEAD:$BRANCH` targets whatever the variable holds, which is
# usually a topic branch. Calibration turned up a workflow doing exactly that
# and being reported as writing to the default branch, so a refspec whose
# destination is a variable is explicitly not a match.
PUSH_TO_VARIABLE = re.compile(r"git\s+push[^\n;|&]*:\s*[\"']?\$", re.IGNORECASE)
PUSH_DEFAULT = re.compile(
    r"git\s+push[^\n;|&]*\b(origin\s+)?(HEAD(:refs/heads/(main|master))?|main|master)\b"
    r"|git\s+push\s+origin\s+HEAD\b",
    re.IGNORECASE,
)
BARE_PUSH = re.compile(r"git\s+push\s*(?:$|[;|&\n])", re.IGNORECASE)
ADMIN_MERGE = re.compile(r"gh\s+pr\s+merge[^\n;|&]*--(admin|auto)\b", re.IGNORECASE)
PUSH_ACTIONS = {"ad-m/github-push-action", "stefanzweifel/git-auto-commit-action"}
DEFAULT_BRANCHES = {"main", "master", "trunk", "develop"}


def _push_action(step) -> tuple[str, int] | None:
    uses = (step.uses or "").split("@")[0]
    if uses not in PUSH_ACTIONS:
        return None
    branch = step.with_.get("branch") or step.with_.get("ref")
    if branch is None:
        return f"{uses} pushes to the checked-out branch", step.line
    if str(branch).lower() in DEFAULT_BRANCHES:
        return f"{uses} pushes to {branch}", step.with_line("branch")
    return None


@rule(
    id="ARK005",
    name="agent-writes-default-branch",
    severity="high",
    owasp="ASI06 Insufficient Human Oversight",
    summary="An agent job pushes to the default branch or merges with --admin",
    explanation=EXPLANATION,
)
def check(context: Context) -> Iterator[Finding]:
    if not context.agents:
        return
    agent_line = context.agents[0].step.line
    agent_name = context.agents[0].name

    for step in context.job.steps:
        hit: tuple[str, int] | None = None
        run = step.run or ""
        line = step.line_for("run")

        if PUSH_TO_VARIABLE.search(run):
            continue
        if PUSH_DEFAULT.search(run) or BARE_PUSH.search(run):
            hit = (f"{step.name} pushes to the default branch", line)
        elif ADMIN_MERGE.search(run):
            hit = (f"{step.name} merges with gh pr merge --admin", line)
        else:
            action_hit = _push_action(step)
            if action_hit is not None:
                hit = action_hit

        if hit is None:
            continue

        text, hit_line = hit
        if "merge" in text:
            fix = (
                "drop --admin so required reviews and checks still apply before "
                "agent output lands on the default branch"
            )
        else:
            fix = (
                "push to a branch and open a pull request instead, so agent output "
                "is reviewed before it reaches the default branch"
            )
        yield context.finding(
            line=hit_line,
            hops=[
                Hop(f"{agent_name} produces changes in job '{context.job.id}'", agent_line),
                Hop(text, hit_line),
            ],
            impact=(
                "agent output reaches the default branch with no review, where it runs "
                "in every workflow that follows"
            ),
            fix=fix,
        )
