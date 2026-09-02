# Prevalence: how often an outsider can reach an agent

Run 2026-09-02.

## The figure

**18 of 49 judgeable workflows (36.7%, Wilson 95% CI 24.7-50.7%), 1 excluded**

Share of workflows containing at least one externally reachable path from attacker-controlled text to a privileged agent action, taken from the hand labels alone. No scanner was run to produce it: it is a claim about workflows, and measuring it with ARKEXA would make it a claim about ARKEXA.

## What the denominator means

The corpus is **unenriched** - every workflow the collection queries returned was kept, whatever it turned out to contain. Nothing was added because it looked interesting or dropped because it looked dull, which is what makes the proportion a statement about the population rather than about the collector.

The population is **workflows in repositories that use agent tooling**, found by searching for known agent actions and inference endpoints. It is not all GitHub workflows, and the figure must not be quoted as though it were.

Of the sampled workflows, **20 contain no agent step at all** by ARKEXA's inventory - they came from repositories that use agent tooling elsewhere. They remain in the denominator, because removing them would silently narrow the population to workflows already known to run an agent and inflate the proportion.

## Interval

Wilson rather than the normal approximation: at this sample size and proportion the textbook interval runs off the end of the scale. The count, the denominator and the interval are always reported together - a percentage published without its denominator gets quoted without it.

This corpus is never used to measure precision or recall.
