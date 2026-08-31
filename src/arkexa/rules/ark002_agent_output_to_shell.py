"""ARK002 - model output is interpolated into a shell command."""

from __future__ import annotations

import re
from typing import Iterator

from ..registry import Context, Finding, rule
from ..taint import MODEL, Hop

EXPLANATION = """
A model wrote text, and that text ends up inside a `run:` block, a pipe into a
shell, or an `eval`. Model output is not trusted input: it is a function of the
prompt, and the prompt is often a function of something an outsider wrote. Once
that text is a command line, the injection is a shell injection.

`${{ steps.ai.outputs.text }}` inside `run:` is the worst shape, because the
expression is substituted into the script before the shell ever sees it, so no
amount of quoting inside the script helps.

Fix: put the model output in an environment variable and reference it as
"$VAR", never interpolate it into the script body, and never pipe it into
bash, sh, eval, python -c or node -e.
"""

INTERPRETERS = re.compile(
    r"\|\s*(bash|sh|zsh|python3?|node|ruby|perl)\b"
    r"|\beval\b"
    r"|\b(bash|sh|zsh)\s+-c\b"
    r"|\bpython3?\s+-c\b"
    r"|\bnode\s+-e\b",
    re.IGNORECASE,
)
EXPRESSION_IN_RUN = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)


def _opening(taint) -> str:
    """Only claim an attacker opening when the taint came from one.

    A model answer with no untrusted provenance is still worth reporting, but
    the first line of the path should name whoever fires the trigger.
    """
    if taint.source_path.startswith("steps."):
        return ""
    return taint.phrase


@rule(
    id="ARK002",
    name="agent-output-to-shell",
    severity="critical",
    owasp="ASI05 Unsafe Tool Invocation",
    summary="Model output is interpolated into run: or piped into an interpreter",
    explanation=EXPLANATION,
)
def check(context: Context) -> Iterator[Finding]:
    for step in context.job.steps:
        run = step.run
        if not run:
            continue
        line = step.line_for("run")

        # Direct interpolation: the expression is pasted into the script.
        for expression in EXPRESSION_IN_RUN.findall(run):
            flat = " ".join(expression.split())
            taints = context.taint.of_value(step, "${{ " + flat + " }}", line)
            for taint in taints:
                if taint.kind != MODEL:
                    continue
                final = taint.hop_to(f"the run: block of {step.name}", line)
                yield context.finding(
                    line=line,
                    hops=final.hops,
                    impact=(
                        "model output is substituted into the script before the shell "
                        "parses it, so the model chooses what commands run"
                    ),
                    fix=(
                        "move the value into env: and reference it as \"$VAR\" inside "
                        "the script, so the shell never parses it as code"
                    ),
                    opening=_opening(taint),
                )

        # Indirect: model output is in an env var that gets executed.
        interpreter = INTERPRETERS.search(run)
        if not interpreter:
            continue
        for taint in context.taint.of_run(step):
            if taint.kind != MODEL:
                continue
            final = taint.hop_to(
                f"an interpreter invoked by {step.name} ({interpreter.group(0).strip()})", line
            )
            yield context.finding(
                line=line,
                hops=final.hops,
                impact="model output is executed as code",
                fix=(
                    "never pipe model output into a shell or interpreter; write it to a "
                    "file and inspect it, or constrain it to a fixed set of values"
                ),
                opening=_opening(taint),
            )
