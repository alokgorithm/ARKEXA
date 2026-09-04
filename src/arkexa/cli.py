"""Command line entry point.

No network calls, no API key, no model. A scanner that phones home is a
scanner nobody runs in CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config as config_module
from . import render
from .engine import scan
from .reach import DESCRIPTIONS, LEVELS, rank
from .registry import SEVERITIES, all_rules

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arkexa",
        description="Finds the prompt injections in your CI that an outsider can actually reach.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  nothing reported\n"
            "  1  findings at or above the severity threshold\n"
            "  2  error\n"
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="repository, workflow directory, or a single workflow file (default: .)",
    )
    parser.add_argument(
        "--reachability",
        choices=["external", "contributor", "maintainer", "all"],
        default="external",
        help="lowest reachability to report (default: external)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="output format; sarif uploads to GitHub code scanning",
    )
    parser.add_argument(
        "--only", metavar="IDS", help="comma-separated rule ids, e.g. ARK001,ARK002"
    )
    parser.add_argument(
        "--severity",
        choices=list(SEVERITIES),
        default="low",
        help="lowest severity that sets a non-zero exit code (default: low)",
    )
    parser.add_argument("--explain", metavar="RULE", help="print a rule's explanation and exit")
    parser.add_argument("--list-rules", action="store_true", help="list the rule catalog and exit")
    parser.add_argument(
        "--no-follow", action="store_true", help="do not resolve local composite actions"
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    return parser


def explain(rule_id: str, stream) -> int:
    rules = {rule.id: rule for rule in all_rules()}
    rule = rules.get(rule_id.upper())
    if rule is None:
        stream.write(f"unknown rule {rule_id!r}; try --list-rules\n")
        return EXIT_ERROR
    stream.write(f"{rule.id}  {rule.name}  ({rule.severity})\n")
    stream.write(f"OWASP: {rule.owasp}\n\n")
    stream.write(f"{rule.summary}\n")
    if rule.explanation:
        stream.write(f"\n{rule.explanation}\n")
    stream.write(
        f"\nhttps://github.com/alokgorithm/ARKEXA/blob/main/docs/rules/{rule.id}.md\n"
    )
    return EXIT_CLEAN


def list_rules(stream) -> int:
    for rule in all_rules():
        stream.write(f"{rule.id}  {rule.name:<32} {rule.severity:<8} {rule.summary}\n")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = sys.stdout

    if args.version:
        out.write(f"arkexa {render._version()}\n")
        return EXIT_CLEAN
    if args.list_rules:
        return list_rules(out)
    if args.explain:
        return explain(args.explain, out)

    target = Path(args.target)
    if not target.exists():
        sys.stderr.write(f"arkexa: {target} does not exist\n")
        return EXIT_ERROR

    root = target if target.is_dir() else target.parent
    configuration = config_module.load(root)
    rule_filter = [item.strip() for item in args.only.split(",")] if args.only else None

    try:
        result = scan(
            target,
            config=configuration,
            rule_filter=rule_filter,
            follow_local=not args.no_follow,
        )
    except Exception as exc:  # pragma: no cover - unexpected failure path
        sys.stderr.write(f"arkexa: {exc}\n")
        return EXIT_ERROR

    if not result.scanned and not result.errors:
        sys.stderr.write(f"arkexa: no workflow files found under {target}\n")
        return EXIT_ERROR

    show_all = args.reachability == "all"
    if not show_all:
        floor = rank(args.reachability)
        result.findings = [f for f in result.findings if rank(f.reachability) >= floor]

    if args.format == "json":
        render.render_json(result, out)
    elif args.format == "sarif":
        render.render_sarif(result, out, show_all=show_all)
    else:
        render.render_text(result, out, show_all=show_all)

    if result.errors and not result.findings:
        return EXIT_ERROR
    threshold = SEVERITIES.index(args.severity)
    if any(SEVERITIES.index(f.severity) <= threshold for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
