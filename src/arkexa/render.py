"""Output. A finding is a chain, so print the chain.

A bare line number tells a maintainer that a scanner is unhappy. The path from
the attacker's keyboard to the privileged action tells them what to fix, and
whether to bother.
"""

from __future__ import annotations

import json
import os
import textwrap
from typing import TextIO

from .engine import ScanResult
from .reach import DESCRIPTIONS
from .registry import Finding, all_rules

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[1;33m",
    "medium": "\033[1;36m",
    "low": "\033[1;37m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

COLUMN = 92
WORKFLOW_PREFIX = ".github/workflows/"
GITHUB_PREFIX = ".github/"


def use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _paint(text: str, key: str, enabled: bool) -> str:
    if not enabled or key not in COLORS:
        return text
    return f"{COLORS[key]}{text}{COLORS['reset']}"


def short_path(path: str) -> str:
    """Workflow paths are long and all share a prefix. Drop it for display."""
    if path.startswith(WORKFLOW_PREFIX):
        return path[len(WORKFLOW_PREFIX) :]
    if path.startswith(GITHUB_PREFIX):
        return path[len(GITHUB_PREFIX) :]
    return path


def _aligned(left: str, right: str, indent: int, enabled: bool) -> str:
    """Left text, with file:line pushed to the right margin."""
    room = COLUMN - indent - len(right) - 1
    if len(left) > room:
        left = left[: max(8, room - 2)] + ".."
    pad = max(1, COLUMN - indent - len(left) - len(right))
    return " " * indent + left + " " * pad + _paint(right, "dim", enabled)


def _wrapped(label: str, text: str, indent: int = 2) -> str:
    prefix = " " * indent + label + " "
    body = textwrap.fill(
        text,
        width=COLUMN,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
    )
    return body + "\n"


def render_text(result: ScanResult, stream: TextIO, show_all: bool = False) -> None:
    enabled = use_color(stream)

    for finding in result.findings:
        location = short_path(finding.workflow)
        header_left = f"{finding.severity.upper():<9}{finding.rule}  {finding.name}"
        header_right = f"reachable: {finding.reachability}"
        stream.write(
            _paint(f"{finding.severity.upper():<9}", finding.severity, enabled)
            + f"{finding.rule}  {finding.name}"
            + " " * max(1, COLUMN - len(header_left) - len(header_right))
            + header_right
            + "\n"
        )
        opening_where = short_path(finding.opening_file) if finding.opening_file else location
        stream.write(
            _aligned(
                finding.opening, f"{opening_where}:{finding.opening_line}", 2, enabled
            )
            + "\n"
        )
        for hop in finding.hops:
            where = short_path(hop.file) if hop.file else location
            stream.write(
                _aligned(f"-> {hop.text}", f"{where}:{hop.line}", 4, enabled) + "\n"
            )
        stream.write(_wrapped("=", finding.impact))
        for name, level, line in finding.guards:
            stream.write(_wrapped("note:", f"{name} limits this to {level} ({location}:{line})"))
        stream.write(_wrapped("fix:", finding.fix))
        stream.write("\n")

    _summary(result, stream, enabled, show_all)


def _summary(result: ScanResult, stream: TextIO, enabled: bool, show_all: bool) -> None:
    files = len(result.scanned)
    plural = "s" if files != 1 else ""
    count = len(result.findings)
    if count == 0:
        tail = "reported" if show_all else "reachable by an outsider"
        stream.write(
            _paint("clean", "medium", enabled)
            + f"  {files} workflow file{plural} scanned, nothing {tail}\n"
        )
    else:
        by_severity: dict[str, int] = {}
        for finding in result.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        parts = ", ".join(f"{n} {s}" for s, n in sorted(by_severity.items()))
        stream.write(
            f"{count} finding{'s' if count != 1 else ''} ({parts}) "
            f"in {files} workflow file{plural}\n"
        )
    if not show_all:
        stream.write(
            _paint(
                "  externally reachable findings only; --reachability all for the rest\n",
                "dim",
                enabled,
            )
        )
    if result.suppressed:
        stream.write(f"  {result.suppressed} suppressed by .arkexa.yml\n")
    for problem in result.config.problems:
        stream.write(f"  config: {problem}\n")
    for path, message in result.errors:
        stream.write(f"  could not read {path}: {message.splitlines()[0]}\n")


def to_dict(finding: Finding) -> dict:
    return {
        "rule": finding.rule,
        "name": finding.name,
        "severity": finding.severity,
        "owasp": finding.owasp,
        "workflow": finding.workflow,
        "job": finding.job,
        "line": finding.line,
        "reachability": finding.reachability,
        "reachable_by": DESCRIPTIONS.get(finding.reachability, ""),
        "path": [
            {
                "text": finding.opening,
                "line": finding.opening_line,
                "file": finding.opening_file or finding.workflow,
            },
            *(
                {"text": hop.text, "line": hop.line, "file": hop.file or finding.workflow}
                for hop in finding.hops
            ),
        ],
        "impact": finding.impact,
        "fix": finding.fix,
        "guards": [
            {"name": name, "limits_to": level, "line": line}
            for name, level, line in finding.guards
        ],
    }


def render_json(result: ScanResult, stream: TextIO) -> None:
    payload = {
        "tool": "arkexa",
        "version": _version(),
        "scanned": result.scanned,
        "findings": [to_dict(finding) for finding in result.findings],
        "suppressed": result.suppressed,
        "errors": [{"file": path, "message": message} for path, message in result.errors],
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# GitHub code scanning renders these four. `note` is the floor: nothing ARKEXA
# emits is cosmetic, so nothing maps below it.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _sarif_rules(findings: list[Finding]) -> list[dict]:
    """One descriptor per rule that actually fired, in first-seen order."""
    seen: dict[str, dict] = {}
    known = {rule.id: rule for rule in all_rules()}
    for finding in findings:
        if finding.rule in seen:
            continue
        rule = known.get(finding.rule)
        tags = ["security", "github-actions"]
        if finding.owasp:
            tags.append(finding.owasp.split()[0])
        seen[finding.rule] = {
            "id": finding.rule,
            "name": "".join(part.title() for part in finding.name.split("-")),
            "shortDescription": {"text": rule.summary if rule else finding.name},
            "fullDescription": {"text": rule.summary if rule else finding.impact},
            "help": {
                "text": finding.fix,
                "markdown": (
                    f"**{finding.impact}**\n\n{finding.fix}\n\n"
                    f"See `docs/rules/{finding.rule}.md`."
                ),
            },
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(finding.severity, "warning")
            },
            "properties": {
                "tags": tags,
                "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.0"),
            },
        }
    return list(seen.values())


# GitHub sorts the Security tab by this, and omitting it buries every finding
# under "unknown severity". The numbers are the CVSS bands GitHub documents.
_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
}


def _sarif_result(finding: Finding, index: dict[str, int]) -> dict:
    """One finding, with its exploit path as related locations.

    The path is what makes a finding actionable, so it is carried as
    `relatedLocations` rather than flattened into the message. Code scanning
    shows them as linked steps.
    """
    related = []
    for position, hop in enumerate(
        [(finding.opening, finding.opening_line, finding.opening_file or finding.workflow)]
        + [(hop.text, hop.line, hop.file or finding.workflow) for hop in finding.hops]
    ):
        text, line, file = hop
        related.append({
            "id": position,
            "physicalLocation": {
                "artifactLocation": {"uri": file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, line)},
            },
            "message": {"text": text},
        })

    guards = "".join(
        f" Limited to {level} by {name}." for name, level, _ in finding.guards
    )
    return {
        "ruleId": finding.rule,
        "ruleIndex": index.get(finding.rule, 0),
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": (
                f"{finding.impact} Reachable by: {finding.reachability} - "
                f"{finding.opening}.{guards} {finding.fix}"
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.workflow, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, finding.line)},
            },
            "logicalLocations": [{"name": finding.job, "kind": "function"}],
        }],
        "relatedLocations": related,
        # Keeps an alert stable across re-runs when line numbers move, so
        # code scanning does not close and reopen the same finding.
        "partialFingerprints": {
            "arkexaPath/v1": _fingerprint(finding),
        },
        "properties": {
            "reachability": finding.reachability,
            "job": finding.job,
        },
    }


def _fingerprint(finding: Finding) -> str:
    import hashlib

    material = "|".join([
        finding.rule,
        finding.workflow,
        finding.job,
        *(hop.text for hop in finding.hops),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def render_sarif(result: ScanResult, stream: TextIO, show_all: bool = False) -> None:
    """SARIF 2.1.0, for upload to GitHub code scanning.

    Only the findings the text report would show are emitted. Uploading the
    demoted ones would fill a maintainer's Security tab with alerts the tool
    itself says are not externally reachable, which is the noise problem
    ARKEXA exists to avoid - `--reachability all --format sarif` opts in.
    """
    findings = list(result.findings)
    rules = _sarif_rules(findings)
    index = {rule["id"]: position for position, rule in enumerate(rules)}
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ARKEXA",
                    "informationUri": "https://github.com/alokgorithm/ARKEXA",
                    "version": _version(),
                    "semanticVersion": _version(),
                    "rules": rules,
                }
            },
            "results": [_sarif_result(finding, index) for finding in findings],
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": message},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"}
                            }
                        }],
                    }
                    for path, message in result.errors
                ],
            }],
        }],
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("arkexa")
    except Exception:  # pragma: no cover - running from a source checkout
        from . import __version__

        return __version__
