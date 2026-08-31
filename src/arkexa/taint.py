"""Where untrusted text goes, and where model output goes.

Untrusted input is rarely spelled straight into the sink. It is laundered:

    env:
      BODY: ${{ github.event.issue.body }}
    steps:
      - run: my-agent --prompt "$BODY"

So taint is tracked through three hops that cover almost every real workflow:
workflow / job / step `env`, step outputs written to $GITHUB_OUTPUT, and
environment variables exported to $GITHUB_ENV. Each hop is recorded so the
report can print the chain instead of a bare line number.

Two kinds of taint travel through the same machinery:

    UNTRUSTED   text an attacker wrote (an issue body)
    MODEL       text a model produced (which an attacker may have steered)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from . import data_files
from .loader import line_of
from .model import Job, Step, Workflow

UNTRUSTED = "untrusted"
MODEL = "model"

EXPRESSION = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)
SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
STEP_OUTPUT = re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)")
NEEDS_OUTPUT = re.compile(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)")
ENV_REF = re.compile(r"\benv\.([A-Za-z_][A-Za-z0-9_]*)")
# Inside a composite action or a reusable workflow, `inputs.x` is whatever the
# caller passed, so it is resolved from the caller rather than treated as a
# source of its own.
INPUT_REF = re.compile(r"(?<!github\.event\.)\binputs\.([A-Za-z0-9_-]+)")
WRITE_ENV = re.compile(
    r"^\s*(?:echo|printf)\s+[\"']?([A-Za-z_][A-Za-z0-9_]*)=(.*?)[\"']?\s*>>\s*[\"']?\$\{?GITHUB_ENV\}?",
    re.MULTILINE,
)
WRITE_OUTPUT = re.compile(
    r"^\s*(?:echo|printf)\s+[\"']?([A-Za-z_][A-Za-z0-9_-]*)=(.*?)[\"']?\s*>>\s*[\"']?\$\{?GITHUB_OUTPUT\}?",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Hop:
    """One link in an exploit path.

    `file` is set only when the hop happened somewhere other than the file the
    finding is reported in, which is what makes a chain through a local
    composite action readable.
    """

    text: str
    line: int
    file: str = ""


@dataclass
class Taint:
    """A tainted value, and the route it took to get where it was found.

    tip is the name the value currently goes by, so the next hop can be
    printed as "env.BODY -> prompt of ...".
    """

    kind: str
    label: str
    source_path: str
    phrase: str
    tip: str = ""
    hops: list[Hop] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.tip:
            self.tip = self.source_path

    def hop_to(self, destination: str, line: int) -> "Taint":
        return Taint(
            kind=self.kind,
            label=self.label,
            source_path=self.source_path,
            phrase=self.phrase,
            tip=destination,
            hops=[*self.hops, Hop(f"{self.tip} -> {destination}", line)],
        )

    def as_model(self, destination: str, line: int) -> "Taint":
        """Turn untrusted input into the model output it steered.

        Provenance is kept, so a chain reads all the way from the issue body
        through the model to wherever the answer ends up.
        """
        return Taint(
            kind=MODEL,
            label="model output",
            source_path=self.source_path,
            phrase=self.phrase,
            tip=destination,
            hops=[*self.hops, Hop(f"{self.tip} -> the model answers, as {destination}", line)],
        )


def _sources() -> list[tuple[re.Pattern[str], str, str, str]]:
    compiled = []
    for entry in data_files.untrusted().get("sources", []):
        compiled.append(
            (
                re.compile(entry["path"]),
                entry.get("label", entry["path"]),
                entry["path"],
                entry.get("phrase", "an outsider supplies input"),
            )
        )
    return compiled


_SOURCE_CACHE: list[tuple[re.Pattern[str], str, str, str]] | None = None


def sources() -> list[tuple[re.Pattern[str], str, str, str]]:
    global _SOURCE_CACHE
    if _SOURCE_CACHE is None:
        _SOURCE_CACHE = _sources()
    return _SOURCE_CACHE


def direct_sources(text: str, line: int) -> list[Taint]:
    """Untrusted values named directly inside a ${{ }} expression."""
    found: list[Taint] = []
    seen: set[str] = set()
    for expression in EXPRESSION.findall(text or ""):
        flat = " ".join(expression.split())
        for pattern, label, path, phrase in sources():
            match = pattern.search(flat)
            if match and path not in seen:
                seen.add(path)
                found.append(Taint(UNTRUSTED, label, path, phrase, tip=match.group(0)))
    return found


class JobTaint:
    """Taint tables for one job, built by walking its steps in order.

    Two tables are maintained:

      env      variable name -> taints, seeded from workflow/job/step env
               blocks and updated by any step writing to $GITHUB_ENV
      outputs  (step id, output name) -> taints, from $GITHUB_OUTPUT writes
               and from the outputs of any agent step
    """

    def __init__(
        self,
        workflow: Workflow,
        job: Job,
        agent_step_ids: set[str],
        upstream: dict[str, dict[str, list[Taint]]] | None = None,
        agents_by_id: dict | None = None,
        input_taints: dict[str, list[Taint]] | None = None,
    ) -> None:
        self.workflow = workflow
        self.job = job
        self.agent_step_ids = agent_step_ids
        self.agents_by_id = agents_by_id or {}
        self.input_taints = input_taints or {}
        self.upstream = upstream or {}
        self.env: dict[str, list[Taint]] = {}
        self.outputs: dict[tuple[str, str], list[Taint]] = {}
        self.step_env: dict[int, dict[str, list[Taint]]] = {}
        self._build()

    def _seed(self, block) -> None:
        for name, value in (block or {}).items():
            if not isinstance(value, str):
                continue
            line = line_of(value, self.job.line)
            taints = self._analyze(value, line, self.env)
            if taints:
                self.env[str(name)] = [t.hop_to(f"env.{name}", line) for t in taints]

    def _build(self) -> None:
        self._seed(self.workflow.env)
        self._seed(self.job.env)
        for step in self.job.steps:
            scope = dict(self.env)
            for name, value in step.env.items():
                if not isinstance(value, str):
                    continue
                line = line_of(value, step.line)
                taints = self._analyze(value, line, scope)
                if taints:
                    scope[str(name)] = [t.hop_to(f"env.{name}", line) for t in taints]
            self.step_env[step.index] = scope
            self._apply_writes(step, scope)

    def _apply_writes(self, step: Step, scope: dict[str, list[Taint]]) -> None:
        """A step exporting values for later steps to pick up."""
        run = step.run or ""
        line = step.line_for("run")
        for name, value in WRITE_ENV.findall(run):
            taints = self._analyze(value, line, scope, shell=True)
            if taints:
                self.env[name] = [t.hop_to(f"env.{name}", line) for t in taints]
        if step.id:
            for name, value in WRITE_OUTPUT.findall(run):
                taints = self._analyze(value, line, scope, shell=True)
                if taints:
                    key = f"steps.{step.id}.outputs.{name}"
                    self.outputs[(step.id, name)] = [t.hop_to(key, line) for t in taints]

    def _step_output(self, step_id: str, name: str) -> list[Taint]:
        recorded = self.outputs.get((step_id, name))
        if recorded:
            return recorded
        if step_id not in self.agent_step_ids:
            return []
        path = f"steps.{step_id}.outputs.{name}"
        agent = self.agents_by_id.get(step_id)
        if agent is not None:
            steered = self._prompt_taints(agent)
            if steered:
                return [taint.as_model(path, agent.step.line) for taint in steered]
        return [Taint(MODEL, "model output", path, "a model writes its answer", tip=path)]

    def _prompt_taints(self, agent) -> list[Taint]:
        """Untrusted values that reached this agent's prompt."""
        scope = self.step_env.get(agent.step.index, self.env)
        found: list[Taint] = []
        for surface in agent.prompts:
            for taint in self._analyze(surface.text, surface.line, scope, shell=surface.shell):
                if taint.kind == UNTRUSTED:
                    found.append(taint)
        unique: dict[tuple[str, str], Taint] = {}
        for taint in found:
            unique.setdefault((taint.source_path, taint.tip), taint)
        return list(unique.values())

    def _analyze(
        self, text: str, line: int, scope: dict[str, list[Taint]], shell: bool = False
    ) -> list[Taint]:
        if not text:
            return []
        found: list[Taint] = list(direct_sources(text, line))
        for expression in EXPRESSION.findall(text):
            flat = " ".join(expression.split())
            for step_id, name in STEP_OUTPUT.findall(flat):
                found.extend(self._step_output(step_id, name))
            for job_id, name in NEEDS_OUTPUT.findall(flat):
                found.extend(self.upstream.get(job_id, {}).get(name, []))
            for name in ENV_REF.findall(flat):
                found.extend(scope.get(name, []))
            for name in INPUT_REF.findall(flat):
                found.extend(self.input_taints.get(name, []))
        if shell:
            for name in SHELL_VAR.findall(text):
                found.extend(scope.get(name, []))
        unique: dict[tuple[str, str, str], Taint] = {}
        for taint in found:
            unique.setdefault((taint.kind, taint.source_path, taint.tip), taint)
        return list(unique.values())

    def scope_for(self, step: Step) -> dict[str, list[Taint]]:
        return self.step_env.get(step.index, dict(self.env))

    def of_value(
        self, step: Step, text: str, line: int, shell: bool = False
    ) -> list[Taint]:
        """Taints reaching a piece of text evaluated in this step's scope."""
        return self._analyze(text, line, self.scope_for(step), shell=shell)

    def of_run(self, step: Step) -> list[Taint]:
        return self.of_value(step, step.run or "", step.line_for("run"), shell=True)


def order_jobs(workflow: Workflow) -> list[Job]:
    """Jobs in dependency order, so needs.<job>.outputs can be resolved."""
    ordered: list[Job] = []
    seen: set[str] = set()

    def visit(job: Job, stack: set[str]) -> None:
        if job.id in seen or job.id in stack:
            return
        stack.add(job.id)
        for dependency in job.needs:
            upstream = workflow.jobs.get(dependency)
            if upstream is not None:
                visit(upstream, stack)
        stack.discard(job.id)
        seen.add(job.id)
        ordered.append(job)

    for job in workflow.jobs.values():
        visit(job, set())
    return ordered


class WorkflowTaint:
    """Taint tables for every job, resolved in dependency order."""

    def __init__(
        self,
        workflow: Workflow,
        agent_step_ids: dict[str, set[str]],
        agents_by_id: dict[str, dict] | None = None,
        input_taints: dict[str, list[Taint]] | None = None,
    ) -> None:
        self.workflow = workflow
        self.jobs: dict[str, JobTaint] = {}
        agents_by_id = agents_by_id or {}
        job_outputs: dict[str, dict[str, list[Taint]]] = {}
        for job in order_jobs(workflow):
            table = JobTaint(
                workflow,
                job,
                agent_step_ids.get(job.id, set()),
                upstream=job_outputs,
                agents_by_id=agents_by_id.get(job.id, {}),
                input_taints=input_taints,
            )
            self.jobs[job.id] = table
            job_outputs[job.id] = self._job_outputs(job, table)

    @staticmethod
    def _job_outputs(job: Job, table: JobTaint) -> dict[str, list[Taint]]:
        declared = job.raw.get("outputs")
        result: dict[str, list[Taint]] = {}
        if not isinstance(declared, dict) or not job.steps:
            return result
        last_step = job.steps[-1]
        for name, value in declared.items():
            if not isinstance(value, str):
                continue
            line = line_of(value, job.line)
            taints = table.of_value(last_step, value, line)
            if taints:
                key = f"needs.{job.id}.outputs.{name}"
                result[str(name)] = [t.hop_to(key, line) for t in taints]
        return result

    def for_job(self, job: Job) -> JobTaint:
        return self.jobs[job.id]
