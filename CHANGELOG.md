# Changelog

Notable changes to ARKEXA. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A new rule, or a change that makes an existing rule report more, is a minor
version. A change that makes a rule report less is also a minor version and is
called out explicitly here, because a scanner that goes quiet without saying so
is worse than one that never ran.

## [Unreleased]

Planned for 0.2, in roughly this order:

- ARK006 `secrets-exposed-to-agent`
- ARK007 `unpinned-mcp-server`
- ARK008 `unbounded-agent-loop`
- SARIF output
- a GitHub Action wrapper
- the labelled benchmark corpus and its first published numbers

## [0.1.0] - 2026-08-31

First release. Engine plus five rules.

### Engine

- **Reachability classification.** Every finding is labelled `external`,
  `contributor`, `maintainer` or `unreachable`, derived from the trigger set
  and any `if:` guards. Only `external` is shown by default. Activity types
  are taken into account: `issues: [labeled]` is not externally reachable,
  because labelling an issue needs triage access.
- **Two-hop taint.** Untrusted input is followed through workflow, job and
  step `env`, through `$GITHUB_ENV` and `$GITHUB_OUTPUT` writes, through
  `steps.<id>.outputs.<name>` and across `needs.<job>.outputs.<name>`.
- **Model provenance.** The output of an agent step inherits the taint of the
  prompt that produced it, so a chain reads from the issue body through the
  model to the sink rather than starting at the model.
- **Guard detection.** `author_association` checks, actor allowlists, label
  gates, repository owner checks, non-fork checks and narrowed `permissions:`
  demote a finding instead of being ignored. Negated checks are correctly not
  treated as guards, and an allowlist that includes `NONE` or a first-timer
  association is correctly treated as excluding nobody.
- **Exploit-path output.** Findings print the chain from the attacker to the
  privileged action, never a bare line number.
- **Local composite actions** are followed one level down, carrying the values
  and permissions of the calling job across, with every hop attributed to the
  file it happened in.
- **Line-preserving YAML loader** that keeps `on:` as a string rather than
  letting YAML 1.1 turn it into the boolean `True`.

### Rules

| ID | Name | Severity |
|----|------|----------|
| ARK001 | `untrusted-prompt-write-token` | critical |
| ARK002 | `agent-output-to-shell` | critical |
| ARK003 | `agent-output-to-path` | high |
| ARK004 | `agent-autoapprove` | high |
| ARK005 | `agent-writes-default-branch` | high |

Each ships a vulnerable fixture and a safe fixture, and the safe half is
enforced in CI.

### Interface

- `arkexa [path]`, `--reachability`, `--format text|json`, `--only`,
  `--severity`, `--explain`, `--list-rules`, `--no-follow`, `--version`
- exit `0` clean, `1` findings at or above the threshold, `2` error
- `.arkexa.yml` ignores, each requiring a `reason`

### Known gaps

- Not published to PyPI, so installation is from source.
- The benchmark corpus in `benchmark/` is empty and `results.md` carries no
  numbers. Nothing has been measured yet, and nothing is claimed.
- Composite actions and reusable workflows are resolved one level down only.
- Remote reusable workflows (`uses: owner/repo/.github/workflows/x.yml@ref`)
  are not fetched, since ARKEXA makes no network calls.

[Unreleased]: https://github.com/alokgorithm/ARKEXA/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alokgorithm/ARKEXA/releases/tag/v0.1.0
