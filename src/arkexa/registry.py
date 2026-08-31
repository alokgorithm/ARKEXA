"""Findings, rule registration, and the context a rule is handed."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from .detect import Agent
from .model import Job, Workflow
from .reach import Reachability
from .taint import Hop, JobTaint

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One exploit path, ready to print.

    A finding never carries just a location. It carries the chain that made it
    a finding, which is what convinces a maintainer to fix it.
    """

    rule: str
    name: str
    severity: str
    workflow: str
    job: str
    line: int
    reachability: str
    opening: str
    opening_line: int
    hops: list[Hop]
    impact: str
    fix: str
    # Set when the trigger that opens the path lives in a different file from
    # the finding, which happens for a finding inside a local composite action.
    opening_file: str = ""
    owasp: str = ""
    guards: list[tuple[str, str, int]] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple[int, int, str, int]:
        from .reach import rank

        return (
            SEVERITY_RANK.get(self.severity, 99),
            -rank(self.reachability),
            self.workflow,
            self.line,
        )


@dataclass
class Context:
    """Everything a rule needs about one job."""

    workflow: Workflow
    job: Job
    taint: JobTaint
    agents: list[Agent]
    reach: Reachability

    @property
    def rel(self) -> str:
        return self.workflow.rel

    def finding(
        self,
        line: int,
        hops: Iterable[Hop],
        impact: str,
        fix: str,
        opening: str = "",
        reachability: str | None = None,
    ) -> Finding:
        """Build a finding. The engine stamps rule id, name and severity on it."""
        return Finding(
            rule="",
            name="",
            severity="",
            workflow=self.rel,
            job=self.job.id,
            line=line,
            reachability=reachability or self.reach.level,
            opening=opening or self.reach.phrase,
            opening_line=self.reach.trigger_line,
            hops=list(hops),
            impact=impact,
            fix=fix,
            guards=list(self.reach.guards),
        )


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    owasp: str
    summary: str
    explanation: str
    check: Callable[[Context], Iterator[Finding]]

    def run(self, context: Context) -> list[Finding]:
        findings = list(self.check(context))
        for finding in findings:
            finding.rule = self.id
            finding.name = self.name
            finding.severity = self.severity
            finding.owasp = self.owasp
        return findings


REGISTRY: dict[str, Rule] = {}


def rule(
    *, id: str, name: str, severity: str, owasp: str, summary: str, explanation: str = ""
) -> Callable[[Callable[[Context], Iterator[Finding]]], Callable[[Context], Iterator[Finding]]]:
    """Register a rule. The function yields Findings for one job."""

    def decorate(function: Callable[[Context], Iterator[Finding]]):
        if severity not in SEVERITY_RANK:
            raise ValueError(f"{id}: unknown severity {severity!r}")
        if id in REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        REGISTRY[id] = Rule(
            id=id,
            name=name,
            severity=severity,
            owasp=owasp,
            summary=summary,
            explanation=explanation.strip(),
            check=function,
        )
        return function

    return decorate


def all_rules() -> list[Rule]:
    from . import rules  # noqa: F401  (import registers the rule modules)

    return [REGISTRY[key] for key in sorted(REGISTRY)]
