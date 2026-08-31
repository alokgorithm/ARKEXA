"""Score ARKEXA, and optionally other scanners, against the labelled corpus.

Usage:

    python benchmark/run.py
    python benchmark/run.py --with zizmor --with poutine
    python benchmark/run.py --write        update results.md

Scoring is deliberately generous to the other tools: a scanner is credited with
a true positive if it reports anything at all on a workflow labelled vulnerable,
whether or not it identified the same issue. That framing is the one we would
want applied to us.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

LABELS = HERE / "labels.json"
WORKFLOWS = HERE / "workflows"
RESULTS = HERE / "results.md"


@dataclass
class Score:
    tool: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    total_findings: int = 0
    skipped: bool = False

    @property
    def precision(self) -> float | None:
        reported = self.true_positives + self.false_positives
        return self.true_positives / reported if reported else None

    @property
    def recall(self) -> float | None:
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else None

    def row(self) -> str:
        def percent(value: float | None) -> str:
            return "-" if value is None else f"{value * 100:.0f}%"

        return (
            f"| {self.tool} | {percent(self.precision)} | {percent(self.recall)} | "
            f"{self.true_positives} | {self.false_positives} | "
            f"{self.false_negatives} | {self.total_findings} |"
        )


def load_corpus() -> list[dict]:
    if not LABELS.is_file():
        return []
    data = json.loads(LABELS.read_text(encoding="utf-8"))
    return data.get("workflows", [])


def count_arkexa(path: Path) -> int:
    from arkexa.engine import scan

    return len(scan(path).findings)


def count_external(tool: str, path: Path) -> int | None:
    """Run another scanner and count how many findings it emits."""
    if shutil.which(tool) is None:
        return None
    commands = {
        "zizmor": [tool, "--format", "json", str(path)],
        "poutine": [tool, "-f", "json", str(path)],
    }
    command = commands.get(tool, [tool, str(path)])
    try:
        finished = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        payload = json.loads(finished.stdout or "[]")
    except json.JSONDecodeError:
        # Fall back to the exit code: non-zero means it reported something.
        return 1 if finished.returncode not in (0,) else 0
    if isinstance(payload, list):
        return len(payload)
    for key in ("findings", "results", "vulnerabilities"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def score(tool: str, corpus: list[dict]) -> Score:
    result = Score(tool=tool)
    for entry in corpus:
        path = WORKFLOWS / f"{entry['id']}.yml"
        if not path.is_file():
            continue
        count = count_arkexa(path) if tool == "arkexa" else count_external(tool, path)
        if count is None:
            result.skipped = True
            return result
        result.total_findings += count
        vulnerable = entry.get("label") == "vulnerable"
        if vulnerable and count:
            result.true_positives += 1
        elif vulnerable:
            result.false_negatives += 1
        elif count:
            result.false_positives += 1
        else:
            result.true_negatives += 1
    return result


def report(scores: list[Score], corpus: list[dict]) -> str:
    vulnerable = sum(1 for e in corpus if e.get("label") == "vulnerable")
    clean = sum(1 for e in corpus if e.get("label") == "clean")
    lines = [
        "# Benchmark results",
        "",
        f"Corpus: {len(corpus)} workflows ({vulnerable} vulnerable, {clean} clean).",
        "",
        "| tool | precision | recall | TP | FP | FN | total findings |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in scores:
        if entry.skipped:
            lines.append(f"| {entry.tool} | not installed | | | | | |")
        else:
            lines.append(entry.row())
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with", dest="others", action="append", default=[])
    parser.add_argument("--write", action="store_true", help="update results.md")
    args = parser.parse_args(argv)

    corpus = load_corpus()
    if not corpus:
        print("The corpus is empty. See benchmark/README.md before running this.")
        return 1

    scores = [score("arkexa", corpus)] + [score(name, corpus) for name in args.others]
    text = report(scores, corpus)
    print(text)
    if args.write:
        RESULTS.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
