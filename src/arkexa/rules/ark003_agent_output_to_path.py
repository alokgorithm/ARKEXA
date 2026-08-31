"""ARK003 - model output decides a path, a branch name or a checkout ref."""

from __future__ import annotations

import re
from typing import Iterator

from ..detect import _logical_lines
from ..registry import Context, Finding, rule
from ..taint import MODEL

EXPLANATION = """
Model output is used to build a filesystem path, a git branch name, or the ref
a checkout step resolves. None of those are free-form strings:

  * a path can traverse upwards with ../ and overwrite a workflow file
  * a branch or ref can be pointed at a fork, so a later step checks out and
    runs code the attacker chose
  * a filename can be .github/workflows/anything.yml, which turns a single
    write into persistent execution

The model does not have to be malicious. It only has to be talked into
emitting a string, which is what prompt injection is for.

Note the difference from ARK002: there the model output is parsed as script.
Here it is a perfectly ordinary argument, in a position where the argument
names a location. Writing model output *into* a fixed file is fine, which is
why this rule looks at the path, not at the content.

Fix: derive paths from values you control (a run id, a hash), validate against
an allowlist, or confine writes to a directory created for the purpose.
"""

REF_INPUTS = {"ref", "path", "branch", "base", "head", "working-directory", "file", "filename"}

# A shell variable sitting in a position where the shell reads it as a location.
PATH_POSITION = re.compile(
    r"""(?:
          >>?\s*                                   # redirect target
        | \b(?:cat|cp|mv|rm|tee|touch|mkdir|chmod|chown|source)\s+(?:-\w+\s+)*
        | \bgit\s+(?:checkout|switch)\s+(?:-b\s+)?
        | \bgit\s+branch\s+
        | \bgit\s+push\s+\S+\s+
        | \b(?:--head|--base|--branch|--ref|--path|--file|-C|-b|-o)\s+
        )
        ["']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?
    """,
    re.VERBOSE,
)


def _opening(taint) -> str:
    """Only claim an attacker opening when the taint came from one.

    A model answer with no untrusted provenance is still worth reporting, but
    the first line of the path should name whoever fires the trigger.
    """
    if taint.source_path.startswith("steps."):
        return ""
    return taint.phrase


@rule(
    id="ARK003",
    name="agent-output-to-path",
    severity="high",
    owasp="ASI05 Unsafe Tool Invocation",
    summary="Model output builds a file path, a branch name, or a checkout ref",
    explanation=EXPLANATION,
)
def check(context: Context) -> Iterator[Finding]:
    for step in context.job.steps:
        # An action input that names a location.
        for key, value in step.with_.items():
            if str(key).lower() not in REF_INPUTS or not isinstance(value, str):
                continue
            line = step.with_line(str(key))
            for taint in context.taint.of_value(step, value, line):
                if taint.kind != MODEL:
                    continue
                final = taint.hop_to(f"the {key} input of {step.name}", line)
                yield context.finding(
                    line=line,
                    hops=final.hops,
                    impact=(
                        f"the model chooses the {key} this step resolves, which can point "
                        "at content it also controls"
                    ),
                    fix=(
                        f"set {key} from a value you control, or validate it against an "
                        "allowlist before use"
                    ),
                    opening=_opening(taint),
                )

        run = step.run
        if not run:
            continue

        scope = context.taint.scope_for(step)
        reported: set[str] = set()
        for command, line in _logical_lines(run, step.line_for("run")):
            for variable in PATH_POSITION.findall(command):
                for taint in scope.get(variable, []):
                    if taint.kind != MODEL or taint.source_path in reported:
                        continue
                    reported.add(taint.source_path)
                    final = taint.hop_to(
                        f"a path or ref in {step.name} (${variable})", line
                    )
                    yield context.finding(
                        line=line,
                        hops=final.hops,
                        impact=(
                            "the model chooses where this step writes or what it checks "
                            "out; a path can traverse into .github/workflows and persist"
                        ),
                        fix=(
                            "build paths and branch names from values you control, and "
                            "confine writes to a dedicated directory"
                        ),
                        opening=_opening(taint),
                    )
