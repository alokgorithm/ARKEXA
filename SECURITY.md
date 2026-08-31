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

1. **Private report first.** Any confirmed, externally-reachable critical
   finding in a third-party repository is reported privately to that project
   before it appears anywhere public — through GitHub private vulnerability
   reporting where enabled, otherwise a maintainer email or a security contact
   listed in the repository.
2. **90 days.** Maintainers get 90 days from the private report before any
   public description. The clock pauses if they are actively working on a fix
   and ask for more time.
3. **No repository names.** The benchmark and any published statistics report
   aggregates only. No repository, organisation, or maintainer is named, and no
   finding is attributed to an identifiable project.
4. **No exploits.** No proof-of-concept payload, working injection string, or
   exploitation walkthrough for a live third-party workflow is published, ever.
   Vulnerable examples in this repository are synthetic fixtures written by the
   maintainers.
5. **No unauthorised testing.** ARKEXA reads workflow files. It never sends a
   request to another project's CI, never opens an issue or pull request to
   probe behaviour, and never attempts to trigger a workflow it has analysed.
6. **Withdrawal on request.** If a maintainer asks for their repository to be
   excluded from the benchmark corpus, it is removed and the numbers are
   recomputed.

If you believe a published ARKEXA statistic identifies your project, contact
the maintainer and it will be corrected.
