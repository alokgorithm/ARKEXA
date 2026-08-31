"""Score the benchmark corpora, which are two corpora and not one.

A corpus can answer a prevalence question or an accuracy question. It cannot
answer both, and the difference is not a detail of presentation:

  * The **prevalence corpus** is collected by query and never touched again.
    Every workflow that matched is in it, whatever it turned out to contain.
    That is what makes "X% of agentic workflows are externally reachable" a
    statement about the world rather than about the collector.

  * The **evaluation corpus** may be enriched on purpose, because measuring
    recall needs enough vulnerable workflows to divide by. Enrichment is the
    right choice there and a disqualifying one for prevalence: a corpus topped
    up with known-vulnerable examples reports whatever proportion was mixed
    into it.

So the two are computed by separate entry points from separately declared
corpora, and `prevalence()` refuses an enriched one rather than trusting the
caller to remember. A number that would be wrong is not produced and labelled;
it is not produced.

Usage:

    python tools/score.py prevalence
    python tools/score.py evaluation --with zizmor --with poutine
    python tools/score.py evaluation --corpus .benchmark/evaluation --write

Prevalence comes from the hand labels, never from a scanner: it is a claim
about the workflows, and running a tool to measure it would make it a claim
about the tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

PREVALENCE = "prevalence"
EVALUATION = "evaluation"
KINDS = (PREVALENCE, EVALUATION)

# 1.96 is the two-sided normal quantile for 95%. Wilson rather than the normal
# approximation because the counts here are small and the proportion is near
# the boundary, which is exactly where the textbook interval goes out of range.
Z_95 = 1.959963985


class CorpusError(Exception):
    """The corpus cannot answer the question being asked of it."""


@dataclass
class Corpus:
    root: Path
    kind: str
    enriched: bool
    entries: list[dict] = field(default_factory=list)
    declared_duplicates: list[list[str]] = field(default_factory=list)

    @property
    def judgeable(self) -> list[dict]:
        """Labelled either way. `excluded` entries are not evidence of anything."""
        return [e for e in self.entries if e.get("label") in ("vulnerable", "clean")]

    @property
    def excluded(self) -> list[dict]:
        return [e for e in self.entries if e.get("label") == "excluded"]


def load_corpus(directory: Path) -> Corpus:
    """Read a corpus and the claim it is allowed to support.

    A corpus that does not say which kind it is gets no default. Guessing here
    would mean guessing whether a number may be published.
    """
    labels = directory / "labels.json"
    if not labels.is_file():
        raise CorpusError(f"{labels} does not exist")
    data = json.loads(labels.read_text(encoding="utf-8"))

    kind = data.get("corpus")
    if kind not in KINDS:
        raise CorpusError(
            f"{labels} does not declare which corpus it is. Add "
            f'"corpus": "{PREVALENCE}" or "corpus": "{EVALUATION}", and '
            '"enriched": true/false. See METHODOLOGY.md.'
        )
    if "enriched" not in data:
        raise CorpusError(
            f'{labels} does not declare "enriched". A corpus that will not say '
            "whether it was topped up cannot support a prevalence figure."
        )
    return Corpus(
        root=directory,
        kind=kind,
        enriched=bool(data["enriched"]),
        entries=list(data.get("workflows", [])),
        declared_duplicates=[list(c) for c in data.get("normalised_duplicates", [])],
    )


def wilson(successes: int, total: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial proportion."""
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass
class Prevalence:
    reachable: int
    judgeable: int
    excluded: int
    interval: tuple[float, float] | None

    @property
    def proportion(self) -> float | None:
        return self.reachable / self.judgeable if self.judgeable else None

    def describe(self) -> str:
        """Always a count, a denominator and an interval. Never a bare percentage.

        A percentage on its own invites being quoted on its own, and "19% of
        agentic workflows" from a sample of 93 is a different claim from the
        one the sample supports.
        """
        if not self.judgeable:
            return (
                "no judgeable workflows labelled yet - no prevalence figure "
                f"({self.excluded} excluded)"
            )
        low, high = self.interval
        return (
            f"{self.reachable} of {self.judgeable} judgeable workflows "
            f"({self.proportion * 100:.1f}%, Wilson 95% CI "
            f"{low * 100:.1f}-{high * 100:.1f}%), {self.excluded} excluded"
        )


def prevalence(corpus: Corpus) -> Prevalence:
    """The share of agentic workflows an outsider can reach, from the labels.

    Refuses anything but an unenriched prevalence corpus. This is the guard the
    whole module exists for, so it raises rather than returning a flagged
    result that something downstream could print anyway.
    """
    if corpus.kind != PREVALENCE:
        raise CorpusError(
            f"prevalence cannot be computed from a '{corpus.kind}' corpus. "
            "The evaluation corpus may be enriched with vulnerable-skewed "
            "candidates, so its proportion reflects the sampling, not the "
            "population. Use the prevalence corpus."
        )
    if corpus.enriched:
        raise CorpusError(
            "this corpus is marked enriched, so it cannot support a prevalence "
            "figure. An enriched sample reports the proportion that was mixed "
            "into it."
        )
    judgeable = corpus.judgeable
    reachable = [
        e for e in judgeable
        if e.get("label") == "vulnerable" and e.get("reachability") == "external"
    ]
    return Prevalence(
        reachable=len(reachable),
        judgeable=len(judgeable),
        excluded=len(corpus.excluded),
        interval=wilson(len(reachable), len(judgeable)),
    )


def normalise_workflow(text: str) -> str:
    """Workflow content with the things that differ between copies removed.

    Two repositories deploying the same template rarely produce byte-identical
    files: comments get edited and action pins drift. Comparing raw bytes
    therefore finds almost nothing, which is how wf-056 and wf-076 sat in the
    corpus as separate entries until they were spotted by hand.
    """
    lines = []
    for line in text.splitlines():
        line = re.sub(r"#.*$", "", line).rstrip()
        line = re.sub(r"@[0-9a-f]{40}\b", "@PIN", line)
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalise_workflow(text).encode("utf-8")).hexdigest()


def duplicate_clusters(corpus: Corpus) -> list[list[str]]:
    """Ids whose workflows match once comments and pins are ignored.

    Computed from the files when they are present, and unioned with whatever
    the corpus declares, so a corpus shipped without its workflows still knows
    which entries are copies of each other.
    """
    groups: dict[str, list[str]] = {}
    for entry in corpus.entries:
        path = corpus.root / "workflows" / f"{entry['id']}.yml"
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        groups.setdefault(fingerprint(text), []).append(entry["id"])

    found = [sorted(ids) for ids in groups.values() if len(ids) > 1]
    for declared in corpus.declared_duplicates:
        if sorted(declared) not in found:
            found.append(sorted(declared))
    return sorted(found)


def collapsed_ids(corpus: Corpus) -> set[str]:
    """Entries to skip so one workflow cannot be weighted twice in a tool score.

    Evaluation only. Prevalence counts every deployment, because two
    repositories running the same reachable template are two real exposures -
    see the labelling policy in METHODOLOGY.md.
    """
    skip: set[str] = set()
    for cluster in duplicate_clusters(corpus):
        skip.update(cluster[1:])
    return skip


@dataclass
class Score:
    tool: str
    version: str = "unknown"
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

        if self.skipped:
            return f"| {self.tool} | not installed | | | | | | |"
        return (
            f"| {self.tool} | {self.version} | {percent(self.precision)} | "
            f"{percent(self.recall)} | {self.true_positives} | "
            f"{self.false_positives} | {self.false_negatives} | "
            f"{self.total_findings} |"
        )


def arkexa_version() -> str:
    try:
        from arkexa import __version__

        return str(__version__)
    except Exception:
        return "unknown"


def tool_version(tool: str) -> str:
    if shutil.which(tool) is None:
        return "not installed"
    try:
        finished = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (finished.stdout or finished.stderr or "unknown").strip().splitlines()[0]


def count_arkexa(path: Path) -> int:
    """Externally reachable findings only - what a user sees without asking."""
    from arkexa.engine import scan

    result = scan(path)
    return len([f for f in result.findings if f.reachability == "external"])


def count_external(tool: str, path: Path) -> int | None:
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
        return 1 if finished.returncode != 0 else 0
    if isinstance(payload, list):
        return len(payload)
    for key in ("findings", "results", "vulnerabilities"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def evaluate(corpus: Corpus, tool: str) -> Score:
    """Precision and recall for one tool. Says nothing about prevalence."""
    version = arkexa_version() if tool == "arkexa" else tool_version(tool)
    result = Score(tool=tool, version=version)
    collapsed = collapsed_ids(corpus)
    for entry in corpus.judgeable:
        if entry["id"] in collapsed:
            continue
        path = corpus.root / "workflows" / f"{entry['id']}.yml"
        if not path.is_file():
            continue
        count = count_arkexa(path) if tool == "arkexa" else count_external(tool, path)
        if count is None:
            return Score(tool=tool, version=version, skipped=True)
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


def evaluation_report(corpus: Corpus, scores: list[Score]) -> str:
    vulnerable = sum(1 for e in corpus.judgeable if e["label"] == "vulnerable")
    clean = len(corpus.judgeable) - vulnerable
    enriched = (
        "This corpus is **enriched** with vulnerable-skewed candidates. It "
        "measures precision and recall only, and says nothing about how common "
        "any of this is in the wild - see the prevalence corpus for that."
        if corpus.enriched
        else "This corpus is not enriched."
    )
    return "\n".join([
        "# Evaluation results",
        "",
        f"Corpus: {len(corpus.judgeable)} judgeable workflows "
        f"({vulnerable} vulnerable, {clean} clean), {len(corpus.excluded)} excluded.",
        "",
        enriched,
        "",
        "| tool | version | precision | recall | TP | FP | FN | total findings |",
        "|---|---|---|---|---|---|---|---|",
        *(score.row() for score in scores),
        "",
    ])


def prevalence_report(corpus: Corpus, result: Prevalence) -> str:
    return "\n".join([
        "# Prevalence",
        "",
        "Share of agentic workflows containing at least one externally "
        "reachable path from attacker-controlled text to a privileged agent "
        "action, from the hand labels alone.",
        "",
        f"**{result.describe()}**",
        "",
        "This corpus is collected by query and never enriched, which is what "
        "makes the proportion a statement about agentic workflows rather than "
        "about the collection. It is not used to measure precision or recall.",
        "",
    ])


def default_corpus(kind: str) -> Path:
    for base in (ROOT / ".benchmark", ROOT / "benchmark"):
        candidate = base / kind
        if (candidate / "labels.json").is_file():
            return candidate
        if (base / "labels.json").is_file():
            return base
    return ROOT / "benchmark"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the benchmark corpora.")
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser(PREVALENCE, help="how common this is, from the labels")
    one.add_argument("--corpus")
    one.add_argument("--write", action="store_true")

    two = sub.add_parser(EVALUATION, help="precision and recall, per tool")
    two.add_argument("--corpus")
    two.add_argument("--with", dest="others", action="append", default=[])
    two.add_argument("--write", action="store_true")

    args = parser.parse_args(argv)
    directory = Path(args.corpus) if args.corpus else default_corpus(args.command)

    try:
        corpus = load_corpus(directory)
        if args.command == PREVALENCE:
            text = prevalence_report(corpus, prevalence(corpus))
            out = directory / "prevalence.md"
        else:
            scores = [evaluate(corpus, "arkexa")]
            scores += [evaluate(corpus, name) for name in args.others]
            text = evaluation_report(corpus, scores)
            out = directory / "results.md"
    except CorpusError as error:
        print(f"score: {error}", file=sys.stderr)
        return 2

    print(text)
    if args.write:
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
