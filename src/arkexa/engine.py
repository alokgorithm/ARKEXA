"""Finding workflows, running rules over them, and resolving local actions."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from . import detect, reach
from .config import Config
from .loader import LineDict, WorkflowParseError, line_of
from .model import Job, Step, Workflow, build
from .registry import Context, Finding, all_rules
from .taint import Hop, Taint, WorkflowTaint

WORKFLOW_SUFFIXES = (".yml", ".yaml")


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    suppressed: int = 0
    config: Config = field(default_factory=Config)


@dataclass
class Prepared:
    """A workflow with its agents and taint tables resolved."""

    workflow: Workflow
    tables: WorkflowTaint
    agents: dict[str, list]


def discover(target: Path) -> list[Path]:
    """Workflow files under a repository, or the single file given."""
    if target.is_file():
        return [target]
    roots = [target / ".github" / "workflows", target / ".gitea" / "workflows"]
    if target.name == "workflows":
        roots.insert(0, target)
    found: list[Path] = []
    for root in roots:
        if root.is_dir():
            found.extend(
                sorted(
                    path
                    for path in root.iterdir()
                    if path.is_file() and path.suffix in WORKFLOW_SUFFIXES
                )
            )
    return found


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def prepare(
    workflow: Workflow, input_taints: dict[str, list[Taint]] | None = None
) -> Prepared:
    """Identify the agent steps in a workflow and build its taint tables."""
    agent_ids: dict[str, set[str]] = {}
    agents_by_job: dict[str, list] = {}
    agents_by_id: dict[str, dict] = {}
    for job_id, job in workflow.jobs.items():
        found = detect.agents_in_job(job)
        agents_by_job[job_id] = found
        agent_ids[job_id] = {a.step.id for a in found if a.step.id}
        agents_by_id[job_id] = {a.step.id: a for a in found if a.step.id}
    tables = WorkflowTaint(workflow, agent_ids, agents_by_id, input_taints=input_taints)
    return Prepared(workflow=workflow, tables=tables, agents=agents_by_job)


def analyze(prepared: Prepared, inherited: reach.Reachability | None = None) -> list[Finding]:
    """Run every rule over every job of one workflow."""
    findings: list[Finding] = []
    rules = all_rules()
    workflow = prepared.workflow
    for job in workflow.jobs.values():
        context = Context(
            workflow=workflow,
            job=job,
            taint=prepared.tables.for_job(job),
            agents=prepared.agents.get(job.id, []),
            reach=inherited or reach.classify(workflow, job),
        )
        for rule_object in rules:
            findings.extend(rule_object.run(context))
    return findings


def _composite_as_job(nested: Workflow) -> Job | None:
    """Present the steps of a composite action as a job, so rules can run."""
    runs = nested.raw.get("runs")
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        return None

    raw = LineDict()
    raw.line = nested.raw.key_line("runs", 1)
    raw.key_lines = {}
    job = Job(id="(composite)", raw=raw, workflow=nested, line=raw.line)
    steps = runs.get("steps")
    if isinstance(steps, list):
        for index, step_raw in enumerate(steps):
            if isinstance(step_raw, dict):
                job.steps.append(
                    Step(index=index, raw=step_raw, job=job, line=line_of(step_raw, raw.line))
                )
    nested.jobs[job.id] = job
    return job


def _passed_inputs(block, table, step, caller_rel: str) -> dict[str, list[Taint]]:
    """Taints of the values a caller hands to a local action.

    Every hop collected here happened in the calling workflow, so it is tagged
    with that file. Without this the chain would claim the issue body was read
    inside the action, which is not where a maintainer would look.
    """
    result: dict[str, list[Taint]] = {}
    if not isinstance(block, dict) or step is None:
        return result
    for name, value in block.items():
        if not isinstance(value, str):
            continue
        line = line_of(value, step.line)
        taints = table.of_value(step, value, line)
        if not taints:
            continue
        carried = []
        for taint in taints:
            passed = taint.hop_to(f"inputs.{name}", line)
            passed.hops = [replace(hop, file=caller_rel) for hop in passed.hops]
            carried.append(passed)
        result[str(name)] = carried
    return result


def _follow_local(prepared: Prepared, repo_root: Path, caller_rel: str) -> list[Finding]:
    """Composite actions and reusable workflows called from this workflow.

    One level down only. Most scanners stop at the top-level file, so anything
    wrapped in a local action is invisible to them. Whatever the caller passes
    in a with block is carried across, so a finding inside the action can still
    name the issue body it came from.
    """
    workflow = prepared.workflow
    findings: list[Finding] = []
    seen: set[Path] = set()
    references: list[tuple[str, dict[str, list[Taint]], int, Job]] = []

    for job in workflow.jobs.values():
        table = prepared.tables.for_job(job)
        if job.uses and job.uses.startswith("./"):
            references.append((job.uses, {}, job.line, job))
        for step in job.steps:
            if step.uses and step.uses.startswith("./"):
                references.append(
                    (
                        step.uses,
                        _passed_inputs(step.with_, table, step, caller_rel),
                        step.line,
                        job,
                    )
                )

    for reference, passed, line, caller_job in references:
        target = reference.split("@")[0]
        candidate = (repo_root / target.removeprefix("./")).resolve()
        paths = (
            [candidate / name for name in ("action.yml", "action.yaml")]
            if candidate.is_dir()
            else [candidate]
        )
        for path in paths:
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            try:
                nested = build(
                    path, path.read_text(encoding="utf-8"), rel=_relative(path, repo_root)
                )
            except (OSError, WorkflowParseError):
                continue
            # The steps of a composite action run inside the calling job, so
            # they hold whatever permissions that job was granted.
            caller_permissions = caller_job.raw.get("permissions")
            if caller_permissions is None:
                caller_permissions = workflow.raw.get("permissions")
            if caller_permissions is not None:
                nested.raw["permissions"] = caller_permissions
                nested.permissions_file = caller_rel

            _composite_as_job(nested)
            if not nested.jobs:
                continue
            nested_prepared = prepare(nested, input_taints=passed)
            inherited = _strongest_reachability(workflow)
            for finding in analyze(nested_prepared, inherited=inherited):
                finding.opening_file = caller_rel
                finding.opening_line = workflow.on_line
                finding.hops.insert(
                    0, Hop(f"{caller_rel} calls {target}", line, file=caller_rel)
                )
                findings.append(finding)
    return findings


def _strongest_reachability(workflow: Workflow) -> reach.Reachability:
    best = reach.Reachability(level="unreachable", trigger_line=workflow.on_line)
    for job in workflow.jobs.values():
        candidate = reach.classify(workflow, job)
        if reach.rank(candidate.level) > reach.rank(best.level):
            best = candidate
    return best


def scan(
    target: Path,
    config: Config | None = None,
    rule_filter: Iterable[str] | None = None,
    follow_local: bool = True,
) -> ScanResult:
    config = config or Config()
    wanted = {r.upper() for r in rule_filter} if rule_filter else None
    result = ScanResult(config=config)
    repo_root = target if target.is_dir() else target.parent

    for path in discover(target):
        rel = _relative(path, repo_root)
        try:
            workflow = build(path, path.read_text(encoding="utf-8"), rel=rel)
        except (WorkflowParseError, OSError) as exc:
            result.errors.append((rel, str(exc)))
            continue

        result.scanned.append(rel)
        prepared = prepare(workflow)
        found = analyze(prepared)
        if follow_local:
            found.extend(_follow_local(prepared, repo_root, rel))

        for finding in found:
            if wanted and finding.rule not in wanted:
                continue
            if config.is_ignored(finding.rule, finding.workflow) is not None:
                result.suppressed += 1
                continue
            result.findings.append(finding)

    result.findings.sort(key=lambda f: f.sort_key)
    return result
