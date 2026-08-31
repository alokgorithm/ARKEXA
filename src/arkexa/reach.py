"""Who can trigger this?

Every finding carries a reachability level. The default report shows only the
findings a stranger can reach, which is the difference between three lines of
output and two hundred.

The level starts at the highest level any trigger reaches, then guards lower
it. A guard never deletes a finding, it demotes it: fix the guard and the
finding drops out of the default report on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import data_files
from .model import Job, Workflow

LEVELS = ("unreachable", "maintainer", "contributor", "external")
_RANK = {name: index for index, name in enumerate(LEVELS)}

DESCRIPTIONS = {
    "external": "any GitHub account, through an issue, a comment or a fork pull request",
    "contributor": "an account with a previously merged pull request",
    "maintainer": "an account with write access",
    "unreachable": "manual dispatch or a schedule only",
}


def rank(level: str) -> int:
    return _RANK.get(level, 0)


def highest(levels) -> str:
    best = "unreachable"
    for level in levels:
        if rank(level) > rank(best):
            best = level
    return best


@dataclass
class Reachability:
    level: str
    trigger: str = ""
    trigger_line: int = 0
    phrase: str = ""
    guards: list[tuple[str, str, int]] = field(default_factory=list)

    @property
    def guarded(self) -> bool:
        return bool(self.guards)


# Activity types only someone with triage or write access can cause. An
# `issues` trigger narrowed to `labeled` is not reachable by a stranger.
PRIVILEGED_TYPES = {
    "labeled", "unlabeled", "assigned", "unassigned", "milestoned",
    "demilestoned", "pinned", "unpinned", "locked", "unlocked",
    "transferred", "deleted", "converted_to_draft",
}


def _trigger_level(event: str, config=None) -> str:
    triggers = data_files.untrusted().get("triggers", {})
    level = "maintainer"
    for candidate in ("external", "contributor", "maintainer", "unreachable"):
        if event in triggers.get(candidate, []):
            level = candidate
            break
    if level == "external" and isinstance(config, dict):
        types = config.get("types")
        if isinstance(types, list) and types:
            if all(str(item) in PRIVILEGED_TYPES for item in types):
                return "maintainer"
    return level


_PHRASES = {
    "issues": "an outsider opens an issue",
    "issue_comment": "an outsider comments on an issue or pull request",
    "pull_request": "an outsider opens a pull request from a fork",
    "pull_request_target": "an outsider opens a pull request from a fork",
    "pull_request_review": "an outsider reviews a pull request",
    "pull_request_review_comment": "an outsider comments on a pull request diff",
    "discussion": "an outsider opens a discussion",
    "discussion_comment": "an outsider comments on a discussion",
    "fork": "an outsider forks the repository",
    "watch": "an outsider stars the repository",
    "workflow_run": "an outsider triggers the upstream workflow",
    "push": "someone with write access pushes",
    "workflow_dispatch": "someone with write access dispatches the workflow",
    "schedule": "the schedule fires",
    "repository_dispatch": "a token holder sends a dispatch",
}


def phrase_for(event: str, level: str = "external", config=None) -> str:
    """The first line of an exploit path: what the attacker actually does."""
    if level != "external" and isinstance(config, dict):
        types = config.get("types")
        if isinstance(types, list) and types:
            listed = ", ".join(str(item) for item in types)
            return f"someone with write access fires {event} ({listed})"
    return _PHRASES.get(event, f"the {event} event fires")


def _negated(condition: str, match: re.Match[str]) -> bool:
    """True when the matched guard is inverted, which makes it not a guard."""
    window = condition[max(0, match.start() - 40) : match.end() + 40]
    return "!=" in window or re.search(r"!\s*(contains|startsWith|github)", window) is not None


def detect_guards(conditions: list[tuple[str, int]]) -> list[tuple[str, str, int]]:
    """Return (name, level, line) for each mitigation found in an `if:`.

    Patterns in guards.yml are ordered most specific first, and only the first
    one to match a given condition counts: an allowlist naming CONTRIBUTOR is
    one guard described two ways, not two guards.

    Across different conditions every guard has to pass, so the effective level
    is the most restrictive of them.
    """
    patterns = [
        (entry["name"], entry["level"], re.compile(entry["pattern"], re.IGNORECASE))
        for entry in data_files.guards().get("conditions", [])
    ]

    matched: list[tuple[str, str, int]] = []
    for condition, line in conditions:
        for name, level, pattern in patterns:
            match = pattern.search(condition)
            if match and not _negated(condition, match):
                if level != "none":
                    matched.append((name, level, line))
                break

    if not matched:
        return []
    strongest = min(rank(level) for _, level, _ in matched)
    seen: set[tuple[str, int]] = set()
    result: list[tuple[str, str, int]] = []
    for name, level, line in matched:
        if rank(level) == strongest and (name, line) not in seen:
            seen.add((name, line))
            result.append((name, level, line))
    return result


def classify(workflow: Workflow, job: Job) -> Reachability:
    """Reachability of a job: its triggers, lowered by any guard on the path."""
    best_level = "unreachable"
    best_event = ""
    best_config = None
    for event, config in workflow.triggers.items():
        level = _trigger_level(event, config)
        if rank(level) > rank(best_level) or not best_event:
            best_level, best_event, best_config = level, event, config

    result = Reachability(
        level=best_level,
        trigger=best_event,
        trigger_line=workflow.on_line,
        phrase=(
            phrase_for(best_event, best_level, best_config)
            if best_event
            else "no trigger declared"
        ),
    )

    guards = detect_guards(job.guard_conditions())
    if guards:
        result.guards = guards
        guard_level = guards[0][1]
        if rank(guard_level) < rank(result.level):
            result.level = guard_level
    return result


def source_reachability(workflow: Workflow, source_path: str) -> str:
    """Cap reachability for sources only reachable through a narrow event.

    A workflow triggered by both `issues` and `workflow_dispatch` is externally
    reachable, but a finding whose taint comes from `github.event.inputs` is
    only reachable by whoever can dispatch it.
    """
    if "inputs" in source_path:
        events = set(workflow.triggers)
        if events <= {"workflow_dispatch", "workflow_call", "schedule"}:
            return "unreachable"
        if "repository_dispatch" in events:
            return "maintainer"
        return "maintainer"
    return "external"
