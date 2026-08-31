"""Score the evaluation corpus. A thin wrapper over `tools/score.py`.

Kept because the README and habit both point here. Everything it does lives in
`tools/score.py`, which is also where the prevalence side lives - one
implementation, so the rule that prevalence never comes from an enriched
corpus cannot be sidestepped by running the other script.

    python benchmark/run.py                          # score ARKEXA
    python benchmark/run.py --with zizmor            # add another scanner
    python tools/score.py prevalence                 # the other question

Scoring is deliberately generous to the other tools: a scanner is credited with
a true positive if it reports anything at all on a workflow labelled
vulnerable, whether or not it identified the same issue. That framing is the
one we would want applied to us.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from score import EVALUATION, main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([EVALUATION, *sys.argv[1:]]))
