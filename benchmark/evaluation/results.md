# Evaluation: precision and recall

Run 2026-09-02.

This corpus is **not enriched**. Recall is therefore measured against however many positives the unbiased sweep happened to contain, which is a smaller number than a purpose-built evaluation corpus would give.

## Scoring basis

Positives are the **externally reachable** vulnerable entries (18), scored against each tool's externally reachable findings. Negatives are the clean entries (27).

The 4 vulnerable entries reachable only by a contributor or maintainer are reported as **demoted**: neither credited nor charged. A default run is not meant to report them, so counting them as misses would penalise the filtering the tool exists to do.

zizmor and poutine do not classify reachability, so every finding they emit counts. That is the generous reading, and the one we would want applied to us.

**Total findings** is reported beside precision on purpose. A scanner that emits two hundred findings to catch twelve real ones is a different proposition from one that emits fourteen, and precision alone does not show it.

| tool | version | precision | recall | TP | FP | FN | demoted | total findings |
|---|---|---|---|---|---|---|---|---|
| arkexa | 0.1.0a1 | 67% | 11% | 2 | 1 | 16 | 4 | 4 |
| zizmor | 1.30.0 | 45% | 83% | 15 | 18 | 3 | 4 | 162 |
| poutine | unavailable | - | - | - | - | - | - | - |

### Tools that could not be run

- **poutine** - no Windows binary is published (Darwin and Linux only), no Go toolchain to build from source, and the Docker daemon is not running; unscored rather than dropped

Their rows are kept rather than dropped: a comparison missing a tool is a different claim from a comparison that tool lost.
