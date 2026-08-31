"""Hand-label benchmark workflows, one at a time, blind.

The benchmark is only worth publishing if a human decided the ground truth
without seeing what the tool being scored had to say. So this script:

  * never imports arkexa, and never shells out to any scanner;
  * shows you the workflow, its triggers and its permissions, and nothing else;
  * records no interpretation of its own - the digest below the file is a
    restatement of two keys, not an opinion about them.

`tests/test_tools.py` enforces the first of those, because a comment is not a
guarantee.

Usage:

    python tools/label.py --labeller AS
    python tools/label.py --labeller AS --limit 20
    python tools/label.py --labeller AS --start wf-031

The corpus defaults to `.benchmark/` when it holds workflows, because that is
where third-party files sit until the disclosure window closes, and falls back
to the published `benchmark/`. Labels are written beside the corpus they
describe, after every single answer, so stopping halfway costs nothing.

The one rule to hold yourself to, when the verdict is close:

    If you cannot write down how an outsider triggers it, it is clean.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
KNOWN_RULES = sorted(p.stem for p in (ROOT / "docs" / "rules").glob("ARK*.md"))
# Only recorded for a vulnerable label, so there is no "unreachable" here:
# a workflow nobody outside can trigger is clean, by the rule below.
REACHABILITY = {
    "e": ("external", "any GitHub account, through an issue, a comment or a fork PR"),
    "c": ("contributor", "an account with a previously merged pull request"),
    "m": ("maintainer", "an account with write access"),
}
RULE = "If you cannot write down how an outsider triggers it, it is clean."


def corpus_dir(explicit: str | None) -> Path:
    if explicit:
        path = (ROOT / explicit).resolve() if not Path(explicit).is_absolute() else Path(explicit)
        if not (path / "workflows").is_dir():
            sys.exit(f"{path / 'workflows'} does not exist")
        return path
    for name in (".benchmark", "benchmark"):
        candidate = ROOT / name
        if candidate.is_dir() and any((candidate / "workflows").glob("*.y*ml")):
            return candidate
    sys.exit("No corpus found. Populate .benchmark/workflows/ or benchmark/workflows/.")


def load_labels(path: Path) -> dict:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "schema": 1,
        "description": (
            "Hand labels for the ARKEXA benchmark corpus, written from the "
            "workflow YAML alone with no scanner output visible. "
            "See ../METHODOLOGY.md."
        ),
        "question": (
            "Can an account with no write access to this repository cause "
            "attacker-controlled text to reach a model in a job that holds a "
            "write scope?"
        ),
        "workflows": [],
        "superseded": [],
    }


def save(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def shas(corpus: Path) -> dict[str, str]:
    """Commit SHAs by id, so the corpus stays reproducible. Repo names stay put."""
    for name in ("sources-private.json", "sources.json"):
        source = corpus / name
        if source.is_file():
            entries = json.loads(source.read_text(encoding="utf-8"))
            if isinstance(entries, dict):
                entries = entries.get("workflows", [])
            return {e["id"]: e.get("sha", "") for e in entries if "id" in e}
    return {}


def triggers_of(document: object) -> dict:
    """The `on:` block. PyYAML reads a bare `on` as the boolean True."""
    if not isinstance(document, dict):
        return {}
    for key in ("on", True, "On", "ON"):
        if key in document:
            value = document[key]
            if isinstance(value, str):
                return {value: None}
            if isinstance(value, list):
                return {event: None for event in value}
            if isinstance(value, dict):
                return value
    return {}


def render_permissions(value: object) -> str:
    if value is None:
        return "(not declared - inherits the repository default)"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items()) or "(empty)"
    return str(value)


def digest(text: str) -> list[str]:
    """Triggers and permissions, restated. No judgement, no third key."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"  could not parse this file as YAML: {error}"]
    if not isinstance(document, dict):
        return ["  this file does not parse into a mapping"]

    lines = ["  triggers"]
    events = triggers_of(document)
    if not events:
        lines.append("    (none declared)")
    for event, filters in events.items():
        if isinstance(filters, dict) and filters:
            detail = "; ".join(f"{k}: {v}" for k, v in filters.items())
            lines.append(f"    {event}  ({detail})")
        else:
            lines.append(f"    {event}")

    lines.append("  permissions")
    lines.append(f"    workflow: {render_permissions(document.get('permissions'))}")
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            declared = job.get("permissions")
            if declared is None and document.get("permissions") is not None:
                continue
            lines.append(f"    job '{name}': {render_permissions(declared)}")
    return lines


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        raise SystemExit("stdin closed; nothing further was written")


def ask_required(prompt: str) -> str | None:
    """Keep asking until there is an answer, or the labeller backs out."""
    while True:
        answer = ask(prompt)
        if answer:
            return answer
        print(f"  Required. Leave it blank again to go back to the verdict.\n  {RULE}")
        if not ask(prompt):
            return None


def judge(entry_id: str, text: str, position: str) -> dict | None:
    print("\n" + "=" * 78)
    print(f"  {entry_id}   {position}")
    print("=" * 78)
    print(text.rstrip("\n"))
    print("-" * 78)
    for line in digest(text):
        print(line)
    print("-" * 78)

    while True:
        verdict = ask("verdict  [v]ulnerable  [c]lean  e[x]clude  [s]kip  [q]uit: ").lower()
        if verdict in ("q", "quit"):
            return {"__quit__": True}
        if verdict in ("s", "skip"):
            return None
        if verdict in ("x", "exclude"):
            reason = ask_required("  why is it not judgeable? ")
            if reason is None:
                continue
            return {"label": "excluded", "rationale": reason}
        if verdict in ("c", "clean"):
            reason = ask_required("  why is it safe? ")
            if reason is None:
                continue
            return {"label": "clean", "reachability": "", "expected_rules": [], "rationale": reason}
        if verdict in ("v", "vulnerable"):
            level = ""
            while not level:
                choice = ask("  who can reach it?  [e]xternal [c]ontributor [m]aintainer: ").lower()
                if choice in REACHABILITY:
                    level, description = REACHABILITY[choice]
                    print(f"    {level}: {description}")
                elif choice:
                    print("    Answer e, c or m.")
                else:
                    break
            if not level:
                continue
            path = ask_required("  how does that account reach the model? ")
            if path is None:
                continue
            rules = ask(f"  rules a correct scanner should report {KNOWN_RULES} (optional): ")
            return {
                "label": "vulnerable",
                "reachability": level,
                "expected_rules": [r.strip().upper() for r in rules.split(",") if r.strip()],
                "rationale": path,
            }
        print("  Answer v, c, x, s or q.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Label benchmark workflows by hand.")
    parser.add_argument("--labeller", required=True, help="your initials, recorded per label")
    parser.add_argument("--corpus", help="corpus directory (default: .benchmark, else benchmark)")
    parser.add_argument("--out", help="labels file (default: <corpus>/labels.json)")
    parser.add_argument("--limit", type=int, help="stop after this many new labels")
    parser.add_argument("--start", help="begin at this id")
    parser.add_argument("--redo", action="store_true", help="re-present your own earlier labels")
    args = parser.parse_args(argv)

    # Real workflows are full of em dashes and emoji, and a Windows console
    # falls back to cp1252 the moment this is piped or redirected. Encoding is
    # not allowed to be the thing that ends a session forty files in.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    corpus = corpus_dir(args.corpus)
    out = Path(args.out) if args.out else corpus / "labels.json"
    data = load_labels(out)
    data.setdefault("workflows", [])
    data.setdefault("superseded", [])
    by_id = {e["id"]: e for e in data["workflows"] if "id" in e}
    sha_of = shas(corpus)

    files = sorted((corpus / "workflows").glob("*.y*ml"))
    if args.start:
        files = [f for f in files if f.stem >= args.start]

    mine = sum(1 for e in by_id.values() if e.get("labeller") == args.labeller)
    todo = [
        f for f in files
        if f.stem not in by_id
        or by_id[f.stem].get("labeller") != args.labeller
        or args.redo
    ]

    print(f"corpus     {corpus}")
    print(f"labels     {out}")
    print(f"labeller   {args.labeller}")
    print(f"progress   {mine} of {len(files)} labelled by you, {len(todo)} to go")
    print(f"\n{RULE}\n")

    written = 0
    for index, path in enumerate(todo, start=1):
        if args.limit and written >= args.limit:
            print(f"\nStopping at --limit {args.limit}.")
            break
        entry_id = path.stem
        position = f"{index} of {len(todo)} in this run, {mine + written} done overall"
        answer = judge(entry_id, path.read_text(encoding="utf-8", errors="replace"), position)
        if answer is None:
            continue
        if answer.get("__quit__"):
            break

        previous = by_id.get(entry_id)
        if previous is not None:
            data["superseded"].append(previous)
            data["workflows"].remove(previous)
        entry = {
            "id": entry_id,
            "sha": sha_of.get(entry_id, ""),
            "triggers": sorted(str(e) for e in triggers_of(_parse(path)).keys()),
            **answer,
            "labeller": args.labeller,
            "reviewed": dt.date.today().isoformat(),
        }
        data["workflows"].append(entry)
        data["workflows"].sort(key=lambda e: e["id"])
        by_id[entry_id] = entry
        save(out, data)
        written += 1
        print(f"  recorded {entry_id} as {entry['label']}")

    counts: dict[str, int] = {}
    for entry in data["workflows"]:
        counts[entry["label"]] = counts.get(entry["label"], 0) + 1
    totals = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"
    print(f"\n{written} labelled this run. Totals: {totals}")
    print(f"Written to {out}")
    return 0


def _parse(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return {}


if __name__ == "__main__":
    raise SystemExit(main())
