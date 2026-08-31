"""Identifying the step where a model reads text.

Everything ARKEXA reports hangs off this: a workflow with no agent step is not
its problem. Signatures live in data/agents.yml so that adding a new agent CLI
is a one-line pull request.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from . import data_files
from .model import Job, Step, Workflow


@dataclass
class PromptSurface:
    """A piece of text this step hands to a model."""

    text: str
    line: int
    where: str
    shell: bool = False


@dataclass
class Agent:
    """An identified agent step."""

    name: str
    kind: str
    step: Step
    prompts: list[PromptSurface] = field(default_factory=list)
    command_lines: list[tuple[str, int]] = field(default_factory=list)
    implicit_event: bool = False

    @property
    def label(self) -> str:
        return self.step.name


def _logical_lines(script: str, base_line: int) -> list[tuple[str, int]]:
    """Split a run block into command lines, joining backslash continuations."""
    result: list[tuple[str, int]] = []
    buffer: list[str] = []
    start = base_line
    for offset, raw in enumerate(script.splitlines()):
        line_number = base_line + offset
        if not buffer:
            start = line_number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        text = " ".join(part.strip() for part in buffer).strip()
        if text:
            result.append((text, start))
        buffer = []
    if buffer:
        text = " ".join(part.strip() for part in buffer).strip()
        if text:
            result.append((text, start))
    return result


def _first_words(command: str) -> list[str]:
    """Executable names in a command line, following pipes and separators."""
    words: list[str] = []
    expect = True
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        if expect:
            words.append(token.split("/")[-1])
            expect = False
        if token in ("|", "&&", "||", ";", "&"):
            expect = True
        elif token.endswith(("|", ";")) and len(token) > 1:
            expect = True
    for separator in ("|", "&&", "||", ";"):
        for chunk in command.split(separator):
            chunk = chunk.strip()
            if chunk:
                head = chunk.split()[0].split("/")[-1]
                if head not in words:
                    words.append(head)
    return words


def agent_for_step(step: Step) -> Agent | None:
    """Return an Agent when this step hands text to a model, else None."""
    data = data_files.agents()

    uses = step.uses or ""
    if uses:
        reference = uses.split("@")[0].strip()
        for entry in data.get("actions", []):
            if reference.lower().startswith(entry["uses"].lower()):
                agent = Agent(
                    name=entry["name"],
                    kind="action",
                    step=step,
                    implicit_event=bool(entry.get("implicit_event")),
                )
                for key in entry.get("prompt_inputs", []):
                    value = step.with_.get(key)
                    if isinstance(value, str) and value.strip():
                        agent.prompts.append(
                            PromptSurface(value, step.with_line(key), f"the {key} input")
                        )
                return agent

    run = step.run
    if not run:
        return None
    lines = _logical_lines(run, step.line_for("run"))
    for command, line in lines:
        words = _first_words(command)
        for entry in data.get("commands", []):
            if entry["exe"] in words:
                agent = Agent(name=entry["name"], kind="command", step=step)
                agent.command_lines.append((command, line))
                agent.prompts.append(
                    PromptSurface(command, line, f"the {entry['exe']} command line", shell=True)
                )
                return agent
        for host in data.get("endpoints", []):
            if host in command:
                agent = Agent(name=f"call to {host}", kind="endpoint", step=step)
                agent.command_lines.append((command, line))
                agent.prompts.append(
                    PromptSurface(command, line, f"the request body sent to {host}", shell=True)
                )
                return agent
    return None


def agents_in_job(job: Job) -> list[Agent]:
    found = []
    for step in job.steps:
        agent = agent_for_step(step)
        if agent is not None:
            found.append(agent)
    return found


def agent_step_ids(workflow: Workflow) -> dict[str, set[str]]:
    """Job id -> ids of the steps in it that run an agent.

    Used by the taint engine to mark every output of an agent step as model
    output without having to know that action's output names.
    """
    mapping: dict[str, set[str]] = {}
    for job_id, job in workflow.jobs.items():
        ids = {agent.step.id for agent in agents_in_job(job) if agent.step.id}
        mapping[job_id] = ids
    return mapping


AUTOAPPROVE_CACHE: list[tuple[re.Pattern[str], str, str]] | None = None


def autoapprove_flags() -> list[tuple[re.Pattern[str], str, str]]:
    global AUTOAPPROVE_CACHE
    if AUTOAPPROVE_CACHE is None:
        AUTOAPPROVE_CACHE = [
            (re.compile(re.escape(entry["flag"]).replace(r"\ ", r"\s+"), re.IGNORECASE),
             entry["flag"], entry.get("tool", "generic"))
            for entry in data_files.agents().get("autoapprove", [])
        ]
    return AUTOAPPROVE_CACHE
