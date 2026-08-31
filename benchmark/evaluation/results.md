# Benchmark results

**Provisional. Not a headline claim, and not yet the published benchmark.**

The corpus is not in this repository yet. Six of the workflows in it contain
live, externally reachable paths in real projects, and [SECURITY.md](../SECURITY.md)
requires those projects to be told privately, with 90 days, before anything
about them is published. Aggregate statistics are allowed and are what follows.

## What has been measured

Two separate samples, both collected read-only from public repositories, one
workflow per repository, no repository named anywhere.

### Calibration sample - 85 workflows

Used to find and fix false positives. Not an evaluation set: the tool was
changed in response to what it said about these files, so any score on them
would be a score on its own training data.

| | before fixes | after fixes |
|---|---|---|
| workflows reported on by default | 10 | 5 |
| externally reachable findings | 15 | 5 |
| of those, judged wrong by hand | 6 | 0 |
| workflows silent by default | 74 | 80 |

The six wrong findings, and what caused each, are described in the commit that
fixed them. The most important was that the most widely used agent action
performs its own caller-permission check, which is documented by the action and
invisible in the workflow file. ARKEXA was calling those workflows externally
reachable. It now demotes them and says why.

### Evaluation sample - 30 workflows, 25 judged

Collected from repositories that appear nowhere in the calibration sample.
Every workflow was labelled by reading its YAML **before** ARKEXA was run over
it. Five were excluded: two content duplicates of other entries, two whose
prompt is assembled from material that cannot be judged from the workflow
alone, and one that delegates to a remote reusable workflow ARKEXA does not
fetch.

Labels: 6 vulnerable, 19 clean.

**Blind run**, ARKEXA as it stood when the labels were written:

| | |
|---|---|
| reported and vulnerable | 6 |
| reported and clean | 0 |
| not reported and vulnerable | 1 |
| not reported and clean | 19 |

Everything ARKEXA reported was a real path. It missed one.

**After fixing that miss**, it finds all 7. That number is *fitted*: the fix
was made in response to this corpus, so 7 of 7 is not evidence of anything and
is recorded here only so the fix is not mistaken for a measurement. The next
honest number has to come from a corpus collected after the fix.

The miss was caused by two general gaps, not by anything specific to that
workflow:

- `actions/ai-inference` accepts untrusted text through an `input` key that
  fills placeholders in a prompt file. That key was not in the signature list.
- Outputs written in the documented multi-line form, `name<<DELIMITER`, were
  not parsed at all, so taint stopped at any step that used it. This is a
  common idiom and losing it silently was the more serious of the two.

## What this is not

- **Not precision and recall you should quote.** 25 judged workflows is a small
  sample and 6 positives is a very small one. The interval on any percentage
  from it is wide enough that the percentage is not worth printing.
- **Not independently labelled.** One labeller, who is also the author of the
  tool being scored. The rationales are recorded per workflow so that someone
  else can disagree with them, and that review has not happened.
- **Not a comparison.** zizmor and poutine have not been run. They are not
  trying to detect agent-specific issues, so the comparison has to be framed as
  *on agent-specific issues, general scanners find X of N*, and that framing
  needs the full corpus to be worth anything.

## What is needed before this page carries a real number

1. Private disclosure to the six affected projects, and 90 days.
2. A corpus collected after the current fixes, so the evaluation set is not the
   set the tool was repaired against.
3. A second labeller, ideally someone with no stake in ARKEXA.
4. zizmor and poutine run over the identical files at pinned versions.
5. Enough positives that a percentage means something.

Regenerate with `python benchmark/run.py --write` once the corpus lands here.
