# Security Policy

This file covers two different things: reporting a problem **in ARKEXA**, and
the policy ARKEXA's maintainers follow when the tool finds a problem **in
someone else's repository**.

## Reporting a vulnerability in ARKEXA

Use GitHub's private vulnerability reporting on this repository, or email the
maintainer. Please do not open a public issue for a security bug.

Expect an acknowledgement within 7 days. This is a volunteer project with no
paid support, so no fix timeline is promised, but you will get a straight
answer about whether and when it will be addressed.

A false positive or false negative in a rule is a **bug**, not a
vulnerability. Please file those as normal issues so they can be discussed in
public.

## Disclosure policy for findings in other repositories

ARKEXA is a scanner. Running it across public repositories will surface real,
exploitable paths in projects that did not ask to be tested. The following
rules are binding on this project, its benchmark, and anything published under
its name.

1. **Assess impact before choosing a channel.** A rule's severity is not an
   impact assessment. ARK001 is `critical` because the pattern it matches can
   be critical, not because every instance is. Before reporting, write down
   what an attacker actually gains. Code execution, repository writes, or
   access to secrets is one thing; influencing the text a bot posts on the
   attacker's own issue is another. That written assessment decides the
   channel, and it is kept.
2. **Private report first for anything with real impact.** Where the assessed
   impact includes code execution, writes to a repository, exposure of
   secrets, or anything usable against a third party, the finding is reported
   privately before it appears anywhere public — through GitHub private
   vulnerability reporting where enabled, otherwise a maintainer email or a
   security contact listed in the repository.
3. **A public issue is acceptable for an advisory finding**, when all three
   hold: the assessed impact is bounded and excludes everything in rule 2; the
   maintainer has already applied a mitigation, so the report refines an
   existing defence rather than disclosing an absent one; and the report
   contains no exploitable detail. Advisory findings are ordinary maintenance.
   Routing them through a security channel overstates them, and a maintainer
   who opens a private advisory to read that their prompt hardening could be
   slightly better has been misled about what was waiting for them.
4. **90 days.** Where rule 2 applies, maintainers get 90 days from the private
   report before any public description. The clock pauses if they are actively
   working on a fix and ask for more time.
5. **No repository names.** The benchmark and any published statistics report
   aggregates only. No repository, organisation, or maintainer is named, and no
   finding is attributed to an identifiable project.
6. **No exploits.** No proof-of-concept payload, working injection string, or
   exploitation walkthrough for a live third-party workflow is published, ever.
   Vulnerable examples in this repository are synthetic fixtures written by the
   maintainers.
7. **No unauthorised testing.** ARKEXA reads workflow files. It never sends a
   request to another project's CI to probe behaviour, never opens an issue or
   pull request as a test, and never attempts to exercise a workflow in order
   to learn something about it.

   Ordinary contact is not testing. Reporting a finding through a project's
   issue tracker is permitted even when filing the issue fires a workflow that
   runs on `issues` — which is exactly the case for the workflows this tool is
   built to analyse. There is no way to reach those maintainers that does not
   touch their CI. No conclusion is ever drawn from what such a run does, and
   its output is never used as evidence for anything.
8. **Withdrawal on request.** If a maintainer asks for their repository to be
   excluded from the benchmark corpus, it is removed and the numbers are
   recomputed.

If you believe a published ARKEXA statistic identifies your project, contact
the maintainer and it will be corrected.

## Changes to this policy

**2026-09-05.** Rules 1–3 and rule 7 were rewritten after the first four
disclosures went out.

The previous version required a private report for any "externally-reachable
critical finding", taking the rule's severity as the trigger. Four findings
that ARK001 rates `critical` were assessed by hand as advisory — impact
bounded to the text a bot posts in a comment, on workflows whose maintainers
had already added anti-injection instructions to their prompts — and were
reported as public issues instead. That was a defensible call about severity
and did not match the policy as written.

The previous rule 7 also said the project "never attempts to trigger a
workflow it has analysed". Filing those reports through the issue trackers
fired the `issues`-triggered workflows being reported. That is unavoidable
when contacting the maintainer of an issue-triggered workflow, so the rule now
distinguishes probing from ordinary contact rather than forbidding something
no one can comply with.

Both changes describe what was done and what will be done again. They are
recorded here rather than edited in quietly: a project whose central claim is
that it follows its own stated method does not get to revise that method
without saying so. The previous text is in the git history.
