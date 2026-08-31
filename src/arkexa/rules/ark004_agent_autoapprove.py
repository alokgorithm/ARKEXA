"""ARK004 - the agent runs with approvals turned off."""

from __future__ import annotations

import re
from typing import Iterator

from ..detect import autoapprove_flags
from ..registry import Context, Finding, rule
from ..taint import Hop

EXPLANATION = """
The agent is started with its confirmation prompts disabled, or with a tool
allowlist that is really a wildcard. In CI there is no human at the terminal, so
these flags are often added to stop the job hanging - which is exactly why they
are dangerous: the flag that unblocks the job also removes the only control
that stood between a prompt and a tool call.

Severity does not depend on the prompt being tainted. An agent with no approval
gate and a token is a standing risk; taint decides how easy it is to aim.

Fix: allowlist the specific tools the job needs, run the agent in a container
without credentials, or keep approvals on and have the job fail rather than
proceed unattended.
"""

WILDCARD_ALLOWLIST = re.compile(
    r"(allowed[_-]?tools|allow[_-]?tools|tools)\s*[:=]?\s*[\"']?\s*(\*|all|Bash\(\*|Bash$)",
    re.IGNORECASE,
)


def _wildcard_in_inputs(step) -> tuple[str, int] | None:
    for key, value in step.with_.items():
        name = str(key).lower()
        if name not in {"allowed_tools", "allowed-tools", "claude_args", "tools", "settings"}:
            continue
        text = str(value)
        if re.search(r"(^|[\s,\"'\[])\*($|[\s,\"'\]])", text) or "Bash(*" in text:
            return f"{key}: {text.strip()[:60]}", step.with_line(str(key))
        if re.search(r"--dangerously-skip-permissions|--permission-mode\s+bypassPermissions", text):
            return f"{key}: {text.strip()[:60]}", step.with_line(str(key))
    return None


@rule(
    id="ARK004",
    name="agent-autoapprove",
    severity="high",
    owasp="ASI02 Tool Misuse and Excessive Agency",
    summary="Agent runs with approvals disabled or a wildcard tool allowlist",
    explanation=EXPLANATION,
)
def check(context: Context) -> Iterator[Finding]:
    permissions = context.job.permissions
    # An agent with no approval gate and no write scope cannot do much with the
    # token it was not given. Calibration against real workflows showed this
    # shape is common and reporting it is noise, so the rule now needs the job
    # to actually hold something worth misusing.
    if permissions.declared and not permissions.write_scopes:
        return

    for agent in context.agents:
        step = agent.step
        hit: tuple[str, int] | None = None

        for command, line in agent.command_lines:
            for pattern, flag, tool in autoapprove_flags():
                if pattern.search(command):
                    hit = (f"{agent.name} runs with {flag}", line)
                    break
            if hit:
                break

        if hit is None:
            hit = _wildcard_in_inputs(step)
            if hit is not None:
                hit = (f"{agent.name} is configured with {hit[0]}", hit[1])

        if hit is None:
            continue

        text, line = hit
        level, guards = context.demoted(agent)
        hops = [
            Hop(text, line),
            Hop(
                f"job '{context.job.id}' {permissions.describe()}",
                permissions.line or context.job.line,
                file=permissions.file,
            ),
        ]
        yield context.finding(
            line=line,
            hops=hops,
            impact=(
                "there is no approval step between the model deciding to act and the "
                "action happening, and the runner holds a token"
            ),
            fix=(
                "allowlist only the tools this job needs, or run the agent without "
                "credentials on the runner"
            ),
            reachability=level,
            guards=guards,
        )
