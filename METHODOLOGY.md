# Benchmark methodology

The tool is not what spreads. This is.

## Two claims, and therefore two corpora

The original plan was one corpus answering both questions. It cannot. The two
claims need opposite things from a sample, and running them off the same files
would quietly corrupt the first:

> **Prevalence.** Of public workflows in which an LLM agent participates, what
> share contain at least one externally reachable path from
> attacker-controlled text to a privileged agent action?

> **Accuracy.** On agent-specific issues, what precision and recall do ARKEXA,
> zizmor and poutine achieve, at pinned versions?

Prevalence needs a sample nobody curated: every workflow the queries returned,
kept whatever it turned out to contain. Accuracy needs *enough vulnerable
workflows to divide by* — with a handful of positives, recall moves in jumps of
twenty points and means nothing.

Enriching to fix the second destroys the first. A corpus topped up with
known-vulnerable examples reports whatever proportion was mixed into it, and
nothing in the output would reveal it. So they are separate corpora, in
separate directories, with separately declared claims, and `tools/score.py`
refuses to compute a prevalence from an enriched one.

Nobody publishes precision numbers for CI scanners. That is the gap.

### The prevalence corpus — `benchmark/prevalence/`

**Never enriched.** Supports exactly one claim: the share of agentic workflows
an outsider can reach.

1. GitHub code search for workflow files referencing known agent actions and
   inference endpoints (the same list as `data/agents.yml`).
2. Deduplicate by repository; at most one workflow per repository, so no single
   project can skew the numbers.
3. Stratify by trigger type so `schedule`-only workflows are not
   over-represented — they are the easy case for reachability.
4. **Keep everything the queries returned.** No workflow is added because it
   looked interesting and none is dropped because it looked dull. Only
   genuinely unjudgeable entries are excluded, and they leave the denominator
   rather than becoming `clean`.
5. Record the commit SHA for every workflow, privately. The corpus must be
   reproducible even after upstream fixes land.

The prevalence figure is computed **from the hand labels, never from a
scanner** — it is a claim about workflows, and measuring it with ARKEXA would
make it a claim about ARKEXA.

It is reported as a proportion with a **Wilson 95% confidence interval** and
the judgeable *n*: `18 of 93 judgeable workflows (19.4%, Wilson 95% CI
12.4-28.8%)`. Wilson rather than the normal approximation because the counts
are small and the proportion sits near the boundary, which is exactly where the
textbook interval runs off the end of the scale.

**A bare percentage is never emitted.** "19% of agentic workflows are
exploitable" is a different and much stronger claim than one supported by 93
hand-labelled files, and a number published without its denominator will be
quoted without it.

### The evaluation corpus — `benchmark/evaluation/`

**May be enriched** with vulnerable-skewed candidates, deliberately, so that
recall has enough positives to be worth reporting. Supports precision, recall,
and total findings per tool at pinned versions.

**It says nothing about prevalence, and no prevalence figure may be derived
from it — not with a caveat, not in passing.** Its proportion of vulnerable
workflows is a property of how it was assembled. `labels.json` declares
`"enriched": true`, `results.md` says so in the header, and the scorer raises
rather than producing a number that would need a footnote to be honest.

Enrichment sources are recorded so the skew is legible: which entries came from
the unbiased sweep, which were added, and why.

## Labelling

Each workflow gets a label in `labels.json`:

```json
{
  "id": "wf-014",
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
- **Every label records who wrote it.** `labeller` and `reviewed` are not
  bookkeeping; a label whose author is unknown cannot be audited, defended, or
  reproduced, and so cannot be ground truth.
- **A label carries judgment, never identity.** No sha, no path, no repository
  or org name, no URL — in the fields *or* in the rationale prose. Describe the
  workflow structurally: the trigger, the scopes, the path from the event to
  the prompt. `tools/label.py` refuses a rationale that names a source, and
  `tests/test_tools.py` fails if an identifying key or value reaches
  `labels.json`.

Use `tools/label.py`, which enforces the rules above and shows the workflow
without any scanner output. Re-presenting a workflow is as blind as the first
pass: the tool does not display, or pre-fill from, a verdict already on file.
Two passes that agree are only evidence if the second was made without sight
of the first.

### Labels set aside

An initial pass of 30 labels was written before `labeller` was recorded. Its
provenance cannot be established, so it is held in
`.benchmark/labels-unverified.json` and **excluded from all published
numbers** — not scored, not counted, not cited. Those verdicts were not
migrated into `labels.json`, and the workflows they covered are being labelled
again from scratch. Discarding 30 labels costs a day. Publishing precision
figures resting on labels nobody can vouch for costs the whole result.

## Measurement

Two entry points, because they answer different questions from different
corpora and must not be run over each other's:

```bash
python tools/score.py prevalence                      # the prevalence corpus
python tools/score.py evaluation --with zizmor --with poutine
```

`tools/score.py` is the only implementation; `benchmark/run.py` delegates to
it, so the rule cannot be sidestepped by running the other script. A corpus
that does not declare `"corpus"` and `"enriched"` is refused outright rather
than assumed — guessing there means guessing whether a number may be
published.

Run ARKEXA, zizmor and poutine over the identical evaluation corpus at pinned
versions, recorded in the results table. Record for each tool: true positives,
false positives, false negatives, precision, recall, and total findings
emitted.

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

Published artifacts carry **aggregate statistics and structural descriptions
only**. `labels.json`, `results.md` and anything else that ships describe what
workflows do; they never say whose they are.

The **id-to-source mapping is private**. `corpus_path`, `repo`, the upstream
workflow path, the commit sha and the search query that found each entry live
in `.benchmark/sources-private.json`, which is gitignored and stays that way.
A corpus id is meaningless without it, which is the point.

A commit sha is identity, not metadata: it is globally searchable, so
publishing one names the repository as surely as writing the name would. That
is why SHAs are held privately rather than shipped alongside the labels.

**Reproducibility is served by publishing the procedure, not the corpus.** The
selection steps above — the search queries, the deduplication rule, the
stratification, the labelling rules and the exclusion criteria — are what let
someone rebuild an equivalent corpus and check whether the numbers hold. A
corpus that can only be reproduced by republishing other people's
vulnerabilities is not reproducible, it is a disclosure.

SHAs may be released later, after every disclosure window has closed, at the
maintainer's discretion. That is a decision to be taken deliberately and once,
not a default — and nothing in the tooling assumes it will happen.

`results.md` holds the numbers, the pinned tool versions, the corpus size, and
the date. Regenerate it whenever a rule changes — a precision claim from three
releases ago is not a precision claim.
