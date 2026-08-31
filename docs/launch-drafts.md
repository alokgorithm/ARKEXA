# Launch drafts

Drafts only. Nothing here has been posted, and nothing should be posted until
the benchmark exists, because every version below leans on numbers and the
honest set right now is small.

**What is actually defensible today**, and the only claims used below:

- 85 agentic workflows, from 85 unrelated public repositories, scanned
  read-only
- 4 externally reachable findings, all four checked by hand
- 80 of 85 workflows silent by default
- 6 false positives found and fixed during that pass, each now a regression
  test

**Not defensible yet**: precision and recall as percentages, any comparison
with zizmor or poutine, and any claim about how common the problem is. Those
need the labelled corpus. Do not put a percentage in a post until
`benchmark/results.md` has one.

---

## Hacker News (Show HN)

Title, under 80 characters, no adjectives:

```
Show HN: ARKEXA - finds prompt injections in CI that an outsider can reach
```

Body:

```
I kept seeing the same shape in GitHub Actions: a workflow triggered by an
issue or a comment, an AI agent step that reads the issue body, and a job
holding contents: write. That is a path from a stranger's keyboard to a token
that can change the repository, and no existing scanner reports it, because
zizmor and poutine do not know what an agent is and agent-audit does not read
workflows.

ARKEXA reads workflows as agent attack surface. The part I care about is not
the rules, it is that every finding is labelled by who can trigger it:
external, contributor, maintainer, or unreachable. Only external shows by
default. That is the difference between a scanner people keep and one they
mute.

It follows taint through env, $GITHUB_ENV, step outputs and needs.<job>.outputs,
so the common laundered shape is caught:

  env:
    BODY: ${{ github.event.issue.body }}
  steps:
    - run: my-agent --prompt "$BODY"

and it prints the chain rather than a line number, because a line number does
not tell a maintainer whether to care.

The thing I would most like feedback on is the false-positive rate. I scanned
85 agentic workflows from 85 unrelated public repositories and it reported 4
externally reachable findings, all four of which I checked by hand and believe
are real. Getting there meant fixing 6 wrong findings from the first pass. The
most instructive one: claude-code-action refuses to run for callers without
write access, which is documented by the action and invisible in the workflow
file, so ARKEXA was calling the most common agentic workflow in the world
externally reachable. It now demotes those and says why.

No network calls, no API key, no LLM inside the tool. One dependency (PyYAML).
Deterministic, so the same workflow gives the same answer.

It is an alpha and the rules are calibrated against 85 workflows, which is not
many. A labelled benchmark with precision and recall against zizmor and
poutine is the next thing, and the corpus and method are in the repo already.

https://github.com/alokgorithm/ARKEXA
```

Notes on posting: Show HN wants a working thing and a plain description. Do not
editorialise in the title. Be in the thread for the first few hours - on HN the
comments are the post. Expect, and answer honestly:

- *"Isn't this just zizmor?"* No, and the README says what ARKEXA deliberately
  does not do. Run both.
- *"Why Python and not Rust?"* Because a repository has 5 to 50 workflow files
  and both finish instantly. Never claim speed.
- *"Where are your precision numbers?"* Not measured yet, and say exactly that.
  The 4-of-85 figure is a calibration result on an unlabelled sample, not a
  precision claim.

---

## r/devops

Title:

```
I scanned 85 public repos that run AI agents in GitHub Actions. Here is what
the workflows actually look like.
```

Lead with the finding, not the tool:

```
I have been looking at how people wire coding agents into CI, and the pattern
that worries me is boring and everywhere: workflow triggers on issues or
issue_comment, an agent step reads the issue body, and the job holds
contents: write. Whatever an outsider writes in that issue is sitting next to
a token that can push.

Two things I did not expect:

1. Most of it is guarded, and the guards are invisible to scanners. The most
   common agent action refuses to run for callers without write access, and
   that check lives in the action, not in the workflow file. Any tool that
   reads only YAML will call these workflows externally reachable and be
   wrong. Mine did, until I checked.

2. The guards people write are not the ones tools look for. Everyone checks
   github.event.comment.user.login, not github.actor, and the permission check
   usually lives in a separate authorisation job whose output gates the real
   job. Neither shape is what a naive scanner matches on.

I wrote a scanner for this. The design decision I would defend hardest is that
it classifies every finding by who can actually trigger it and only shows the
externally reachable ones by default. On the 85-workflow sample that is 4
findings instead of 24.

[link]

Happy to be told the rules are wrong. False positives are the failure mode
that matters here.
```

---

## r/netsec

r/netsec wants technical substance and dislikes tool promotion. Lead with the
mechanism, and only link at the end.

```
Title: Reachability as a filter for prompt-injection findings in CI workflows

The interesting problem in scanning agentic GitHub Actions workflows is not
detection, it is triage. Almost every workflow that runs an agent has a
dangerous-looking pattern in it. The question is which ones a stranger can
actually reach.

Four things turned out to matter more than the detection rules:

- Trigger analysis has to account for activity types. `issues: [labeled]` is
  not externally reachable, because labelling requires triage access. Treating
  it the same as `issues: [opened]` is a large source of noise.

- Guards are frequently not in the file. The most widely used agent action
  performs its own caller-permission check. A YAML-only scanner cannot see it
  and will over-report unless the behaviour is modelled per action, including
  which inputs switch the check off.

- Taint is laundered. Untrusted text reaches the prompt through env, through
  $GITHUB_ENV written by an earlier step, through step outputs, and across
  needs.<job>.outputs. Single-step analysis misses the common cases.

- Model output needs provenance. When an agent reads an issue body and its
  answer is interpolated into a run: block, the useful report traces the issue
  body through the model to the shell. Starting the chain at the model loses
  the reason it matters.

Write-up of the calibration pass, including the six false positives I found
against real workflows and what caused each: [link]
```

---

## dev.to

Long form, and the most useful of the four because it can carry the reasoning.

```
Title: Your AI code reviewer has a write token and reads issue bodies

Structure:

1. The shape. One workflow, twenty lines, that looks completely reasonable and
   is not. Use the demo from the README.
2. Why existing scanners are quiet about it. Not because they are bad, because
   they were built before agents were in workflows, and they are honest about
   their scope.
3. Why most findings do not matter, and reachability as the fix. This is the
   idea worth spreading even if nobody installs the tool.
4. What calibration against 85 real workflows changed. Lead with the
   claude-code-action mistake - admitting the tool was wrong about the most
   popular action is what makes the rest credible.
5. What to actually do on Monday, whether or not you install anything:
   - do not put untrusted text in a prompt; pass it as a file the agent reads
     as data
   - drop the agent job to contents: read and let a separate unprivileged job
     do the writing
   - gate on author_association, or on a label, and know that labelling
     requires triage access
   - never pipe model output into a shell
6. Link, and an explicit ask for false positives.
```

---

## X / Bluesky

One post, no thread padding:

```
Scanned 85 public repos that run AI agents in GitHub Actions.

The common shape: triggered by an issue, agent reads the body, job holds
contents: write. A stranger's text sits next to a token that can push.

Built a scanner that only reports the ones an outsider can actually reach.

[link]
```

---

## Before any of this goes out

- [ ] `benchmark/results.md` has real numbers, or every post avoids
      percentages entirely
- [ ] any repository found to have a live externally reachable issue has been
      told privately, 90 days ago, per SECURITY.md
- [ ] no repository is named in any post, screenshot, or reply
- [ ] the install line in the README works from a clean machine
- [ ] you have two hours free after posting to answer comments
