# The benchmark

Nobody publishes precision numbers for CI scanners. That is the gap this
directory exists to fill.

The plan, the labelling rules and the ethics that bind it are in
[METHODOLOGY.md](../METHODOLOGY.md). This file describes the mechanics.

## Status

**Not yet collected.** `labels.json` holds the schema and no workflows.
`results.md` will stay empty until the corpus is labelled and the tools are
run. There are no numbers here to cite yet, and none will be invented.

## Layout

```
benchmark/
  workflows/     one .yml per corpus entry, named wf-001.yml upward
  labels.json    the labels, written before any scanner is run
  excluded.json  ambiguous cases, with the reason each was dropped
  results.md     precision and recall, regenerated whenever a rule changes
  run.py         runs the scanners over the corpus and scores them
```

## Adding an entry

1. Copy the workflow into `workflows/wf-0NN.yml` with the comment header
   stripped of anything identifying the repository.
2. Add a record to `labels.json`. Write the `rationale` **before** running any
   scanner - reading a tool output first contaminates the label.
3. If you cannot describe how an outsider triggers it, it is not `vulnerable`.
   If you cannot say why it is safe, it is not `clean`. Either way it goes to
   `excluded.json` instead.

## Scoring

```bash
python benchmark/run.py                 # score ARKEXA
python benchmark/run.py --with zizmor    # add another scanner if installed
```

A tool is credited with a true positive when it reports at least one finding on
a workflow labelled `vulnerable`, and charged a false positive for any finding
on one labelled `clean`. Total findings are reported next to precision, because
"247 findings, 12 of them real" is the number that explains why reachability
filtering exists at all.

zizmor and poutine are not trying to detect agent-specific issues. The honest
framing is *on agent-specific issues, general scanners find X of 30* - not a
claim that they are worse tools. They are both good, and they are both in the
comparison because running all three is the advice we actually give.
