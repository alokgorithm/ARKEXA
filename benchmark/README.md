# The benchmark

Nobody publishes precision numbers for CI scanners. That is the gap this
directory exists to fill.

The plan, the labelling rules and the ethics that bind it are in
[METHODOLOGY.md](../METHODOLOGY.md). This file describes the mechanics.

## Status

**Not yet collected.** Both `labels.json` files hold a schema and no workflows.
No results file will hold a number until a corpus is labelled and the tools are
run. There are no numbers here to cite yet, and none will be invented.

## Two corpora

They answer different questions and are not interchangeable. See
[METHODOLOGY.md](../METHODOLOGY.md).

```
benchmark/
  prevalence/    never enriched; answers "how common is this?"
    workflows/   one .yml per entry, named wf-001.yml upward
    labels.json  declares "corpus": "prevalence", "enriched": false
    excluded.json
  evaluation/    may be enriched; answers "what does each tool catch?"
    workflows/
    labels.json  declares "corpus": "evaluation", "enriched": true
    excluded.json
    results.md   precision and recall, regenerated whenever a rule changes
  run.py         delegates to tools/score.py
```

The prevalence corpus keeps everything the collection queries returned. The
evaluation corpus may be topped up with vulnerable-skewed candidates so recall
has enough positives to measure, which is why **no prevalence figure may come
from it**. `tools/score.py` enforces that rather than trusting anyone to
remember.

## Adding an entry

1. Copy the workflow into the right corpus's `workflows/wf-0NN.yml`, with the
   comment header stripped of anything identifying the repository.
2. Add a record to `labels.json`. Write the `rationale` **before** running any
   scanner - reading a tool output first contaminates the label.
3. If you cannot describe how an outsider triggers it, it is not `vulnerable`.
   If you cannot say why it is safe, it is not `clean`. Either way it goes to
   `excluded.json` instead.

`tools/label.py` does steps 2 and 3 for you, one workflow at a time:

```bash
python tools/label.py --labeller AS           # the whole corpus
python tools/label.py --labeller AS --limit 20 # stop after twenty
python tools/label.py --labeller AS --only prevalence/sample-50.json
```

`--only` restricts the run to the ids in a draw file. Skipping past the rest
by hand is a stray keystroke away from recording a verdict on a workflow that
is not in the sample, and a verdict cannot be unseen.

It shows the workflow, its triggers and its permissions, and refuses to record
a verdict without a written reason. It cannot show you a scanner's opinion
because it cannot reach one - it never imports `arkexa` and never runs a
subprocess, and `tests/test_tools.py` fails if that ever stops being true.
Labels are written after every answer, so stopping halfway costs nothing.

## Scoring

```bash
python tools/score.py prevalence                 # how common it is
python tools/score.py evaluation                 # score ARKEXA
python tools/score.py evaluation --with zizmor   # add another scanner
```

Prevalence is computed from the hand labels, never by running a scanner, and is
always reported as a proportion with a Wilson 95% confidence interval and the
judgeable n — never as a bare percentage.

A tool is credited with a true positive when it reports at least one finding on
a workflow labelled `vulnerable`, and charged a false positive for any finding
on one labelled `clean`. Total findings are reported next to precision, because
"247 findings, 12 of them real" is the number that explains why reachability
filtering exists at all.

zizmor and poutine are not trying to detect agent-specific issues. The honest
framing is *on agent-specific issues, general scanners find X of 30* - not a
claim that they are worse tools. They are both good, and they are both in the
comparison because running all three is the advice we actually give.
