# Benchmark methodology

The tool is not what spreads. This is.

## The claim we want to be able to defend

> Across N public workflows in which an LLM agent participates, X% contain at
> least one externally-reachable path from attacker-controlled text to a
> privileged agent action. On the same corpus, ARKEXA achieves precision P and
> recall R; general-purpose scanners achieve precision P' at recall R'.

Nobody publishes precision numbers for CI scanners. That is the gap.

## Corpus

**Target: 60 workflows.** 30 containing at least one genuine, externally
reachable issue; 30 clean. Both halves come from real public repositories, not
synthetic examples — synthetic corpora prove nothing about precision.

Selection:

1. GitHub code search for workflow files referencing known agent actions and
   inference endpoints (the same list as `data/agents.yml`).
2. Deduplicate by repository; at most one workflow per repository, so no single
   project can skew the numbers.
3. Stratify by trigger type so `schedule`-only workflows are not
   over-represented — they are the easy case for reachability.
4. Record the commit SHA for every workflow. The corpus must be reproducible
   even after upstream fixes land.

## Labelling

Each workflow gets a label in `labels.json`:

```json
{
  "id": "wf-014",
  "sha": "<commit sha>",
  "triggers": ["issue_comment"],
  "label": "vulnerable",
  "reachability": "external",
  "expected_rules": ["ARK001"],
  "rationale": "comment body reaches prompt via env; job holds contents: write",
  "labeller": "initials",
  "reviewed": "YYYY-MM-DD"
}
```

Rules for labelling:

- **Label before running any scanner.** Reading a tool's output first
  contaminates the label and inflates that tool's score.
- **Every `vulnerable` label needs a written exploit path** in `rationale`. If
  you cannot describe how an outsider triggers it, it is not vulnerable.
- **Every `clean` label needs the reason it is safe** — the guard, the trigger,
  the missing write scope.
- **Ambiguous cases are excluded**, not guessed. Record them in
  `excluded.json` with the reason. A smaller honest corpus beats a larger
  hand-wavy one.

## Measurement

Run ARKEXA, zizmor and poutine over the identical corpus at pinned versions.
Record for each tool: true positives, false positives, false negatives,
precision, recall, and total findings emitted.

Report total findings alongside precision. "247 findings, 12 of them real" is
the number that explains why reachability filtering exists.

Compare like with like. zizmor and poutine are not trying to detect agent
issues, so the honest framing is *"on agent-specific issues, general scanners
find X of 30"* — not a claim that they are worse tools.

## Ethics

Binding, and not optional. Full text in [../SECURITY.md](../SECURITY.md).

- Private disclosure to affected maintainers before publication, 90 days.
- Aggregate statistics only. No repository, org, or maintainer named.
- No proof-of-concept payloads published, ever.
- Read-only. Never trigger, probe, or interact with another project's CI.
- Any maintainer may have their workflow removed from the corpus on request.

## Publication

`results.md` holds the numbers, the pinned tool versions, the corpus size, and
the date. Regenerate it whenever a rule changes — a precision claim from three
releases ago is not a precision claim.
