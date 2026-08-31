"""Workflow / Job / Step, plus effective permissions.

The model is deliberately thin: it normalises the shapes GitHub allows (a
trigger can be a string, a list or a mapping; permissions can be a keyword or
a mapping) and keeps a line number on everything a finding might point at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .loader import LineDict, line_of, load_yaml

WRITE_ONLY_SCOPES = {"id-token"}


@dataclass
class Permissions:
    """Effective permissions for a job.

    declared is False when neither the job nor the workflow said anything, in
    which case the token's scopes come from a repository setting we cannot see.
    """

    scopes: dict[str, str] = field(default_factory=dict)
    declared: bool = False
    line: int = 0
    source: str = "default"
    # Set when the permissions were declared in a different file, which is the
    # case for the steps of a local composite action.
    file: str = ""

    @property
    def write_scopes(self) -> list[str]:
        return sorted(
            name
            for name, level in self.scopes.items()
            if level == "write" and name not in WRITE_ONLY_SCOPES
        )

    def describe(self) -> str:
        if not self.declared:
            return "declares no permissions; the default token may hold write"
        writes = self.write_scopes
        if not writes:
            return "holds no write scope"
        return "holds " + ", ".join(f"{s}: write" for s in writes)


def _parse_permissions(raw: Any, source: str) -> Permissions | None:
    if raw is None:
        return None
    line = line_of(raw)
    if isinstance(raw, str):
        if raw == "write-all":
            return Permissions(
                {
                    "contents": "write",
                    "packages": "write",
                    "actions": "write",
                    "issues": "write",
                    "pull-requests": "write",
                },
                True,
                line,
                source,
            )
        return Permissions({}, True, line, source)
    if isinstance(raw, dict):
        return Permissions({str(k): str(v) for k, v in raw.items()}, True, line, source)
    return None


@dataclass
class Step:
    index: int
    raw: LineDict
    job: "Job"
    line: int = 0

    @property
    def id(self) -> str | None:
        value = self.raw.get("id")
        return str(value) if value is not None else None

    @property
    def name(self) -> str:
        """A name to call this step in a report.

        A single-line `run:` names itself well enough. A multi-line one does
        not: quoting its first line next to a finding on its fourth would only
        mislead, so an unnamed multi-line step is called by its position.
        """
        for key in ("name", "uses"):
            if self.raw.get(key):
                return str(self.raw[key])
        run = str(self.raw.get("run", "")).strip().splitlines()
        if len(run) == 1:
            return run[0][:60]
        return f"step {self.index + 1}"

    @property
    def uses(self) -> str | None:
        value = self.raw.get("uses")
        return str(value) if value is not None else None

    @property
    def run(self) -> str | None:
        value = self.raw.get("run")
        return str(value) if value is not None else None

    @property
    def with_(self) -> LineDict:
        value = self.raw.get("with")
        return value if isinstance(value, dict) else LineDict()

    @property
    def env(self) -> LineDict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else LineDict()

    @property
    def if_(self) -> str:
        return str(self.raw.get("if", ""))

    def line_for(self, key: str) -> int:
        if isinstance(self.raw, LineDict):
            return self.raw.key_line(key, self.line)
        return self.line

    def with_line(self, key: str) -> int:
        block = self.with_
        if isinstance(block, LineDict):
            return block.key_line(key, self.line_for("with"))
        return self.line


@dataclass
class Job:
    id: str
    raw: LineDict
    workflow: "Workflow"
    line: int = 0
    steps: list[Step] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.raw.get("name", self.id))

    @property
    def if_(self) -> str:
        return str(self.raw.get("if", ""))

    @property
    def env(self) -> LineDict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else LineDict()

    @property
    def needs(self) -> list[str]:
        value = self.raw.get("needs")
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @property
    def uses(self) -> str | None:
        value = self.raw.get("uses")
        return str(value) if value is not None else None

    @property
    def environment(self) -> str | None:
        value = self.raw.get("environment")
        if isinstance(value, dict):
            value = value.get("name")
        return str(value) if value else None

    @property
    def permissions(self) -> Permissions:
        own = _parse_permissions(self.raw.get("permissions"), f"job {self.id}")
        if own is not None:
            return own
        inherited = _parse_permissions(self.workflow.raw.get("permissions"), "workflow")
        if inherited is not None:
            inherited.file = self.workflow.permissions_file
            return inherited
        return Permissions({}, declared=False, line=self.line, source="default")

    def guard_conditions(self) -> list[tuple[str, int]]:
        found: list[tuple[str, int]] = []
        seen: set[str] = set()
        queue = [self.id]
        while queue:
            job_id = queue.pop()
            if job_id in seen:
                continue
            seen.add(job_id)
            job = self.workflow.jobs.get(job_id)
            if job is None:
                continue
            if job.if_:
                found.append((job.if_, job.raw.key_line("if", job.line)))
            queue.extend(job.needs)
        return found


@dataclass
class Workflow:
    path: Path
    raw: LineDict
    rel: str = ""
    jobs: dict[str, Job] = field(default_factory=dict)
    # Where the workflow-level `permissions:` block was written. Normally this
    # file; for a composite action it is the workflow that calls it.
    permissions_file: str = ""

    @property
    def name(self) -> str:
        return str(self.raw.get("name", self.path.stem))

    @property
    def env(self) -> LineDict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else LineDict()

    @property
    def on_line(self) -> int:
        return self.raw.key_line("on", 1)

    @property
    def triggers(self) -> dict[str, Any]:
        raw = self.raw.get("on")
        if raw is None:
            return {}
        if isinstance(raw, str):
            return {raw: None}
        if isinstance(raw, list):
            return {str(item): None for item in raw}
        if isinstance(raw, dict):
            return {str(key): value for key, value in raw.items()}
        return {}

    def steps(self) -> Iterator[Step]:
        for job in self.jobs.values():
            yield from job.steps


def build(path: Path, text: str, rel: str | None = None) -> Workflow:
    raw = load_yaml(text)
    if not isinstance(raw, dict):
        raw = LineDict()
    workflow = Workflow(path=path, raw=raw, rel=rel or path.name)
    jobs_raw = raw.get("jobs")
    if isinstance(jobs_raw, dict):
        for job_id, job_raw in jobs_raw.items():
            if not isinstance(job_raw, dict):
                continue
            job = Job(
                id=str(job_id),
                raw=job_raw,
                workflow=workflow,
                line=jobs_raw.key_line(str(job_id), line_of(job_raw)),
            )
            steps_raw = job_raw.get("steps")
            if isinstance(steps_raw, list):
                for index, step_raw in enumerate(steps_raw):
                    if not isinstance(step_raw, dict):
                        continue
                    job.steps.append(
                        Step(index=index, raw=step_raw, job=job, line=line_of(step_raw))
                    )
            workflow.jobs[job.id] = job
    return workflow
