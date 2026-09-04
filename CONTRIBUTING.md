# Contributing

The most useful contribution is usually one line.

## Adding an agent

If your team runs an agent CLI or action that ARKEXA does not recognise, add it
to [`src/arkexa/data/agents.yml`](src/arkexa/data/agents.yml) and open a pull
request. No Python required.

```yaml
commands:
  - name: your-agent
    exe: your-agent
    prompt_flags: ["-p", "--prompt"]
```

For an action, give the `uses:` prefix and the `with:` keys whose value reaches
the model:

```yaml
actions:
  - name: your-action
    uses: yourorg/your-action
    prompt_inputs: [prompt, instructions]
```

Set `implicit_event: true` only when the action reads the triggering issue or
comment text by itself, with no prompt input set.

The same goes for [`untrusted.yml`](src/arkexa/data/untrusted.yml) (a new
attacker-controlled field) and [`guards.yml`](src/arkexa/data/guards.yml) (a
mitigation ARKEXA should recognise and stay quiet about).

## Reporting a false positive

A false positive is a bug of exactly the same severity as a false negative, and
it is the more urgent of the two: a scanner that cries wolf gets uninstalled,
and then it catches nothing at all.

Open an issue with the smallest workflow that reproduces it. If you can, say
why the shape is safe - that reason usually becomes a guard in `guards.yml`.

## Working on a rule

Every rule ships with two fixtures in `tests/fixtures`:

- `arkNNN_vulnerable.yml` - the rule must fire
- `arkNNN_safe.yml` - the rule must stay silent, and so must every other rule

A rule without a passing safe fixture is not finished. `test_rules.py` enforces
both halves.

```bash
cd tests && python -m unittest discover -s . -t .   # the suite
python tools/gen_rule_docs.py                        # after changing a rule
```

Rule documentation is generated from the registry and the fixtures. Edit the
`EXPLANATION` string in the rule module, not the Markdown, or CI will tell you
the docs are out of date.

## Scope

This is deliberately a small tool, and staying small is what keeps it
maintainable on a few hours a week. These are out of scope, permanently:

- anything zizmor already does well: template injection into shell,
  `pull_request_target` misuse, unpinned actions, credential persistence,
  excessive permissions in general
- a dashboard, a hosted tier, or a VS Code extension
- an LLM inside the tool, a network call, or an API key

A rule belongs here only if it is specific to an agent participating in a
workflow. If it would fire on a workflow with no model in it, it belongs in
zizmor instead, and a pull request there will help more people.

## Expectations

This is a volunteer project. There is no response-time promise, and a pull
request may sit for a while. Issues that come with a failing fixture get looked
at first, because they are already half solved.

## Security

Do not open a public issue for a vulnerability in ARKEXA, and do not post a
finding from someone else's repository anywhere public. Both are covered by
[SECURITY.md](SECURITY.md), which is binding on this project.

## Code of Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). It
carries two project-specific rules alongside the usual ones: no findings from
other people's repositories, and no working injection payloads.

## Releases

User-visible changes go in [CHANGELOG.md](CHANGELOG.md) under `Unreleased`, in
the same pull request that makes them. A change that makes a rule report less
must be called out there explicitly.

### Tags

Two kinds, and they behave differently on purpose.

**Version tags are immutable.** `v0.1.0a1`, `v0.2.0`, and so on. Each points at
one commit for good and is what `release.yml` publishes to PyPI from — the tag
has to match `__version__` in `src/arkexa/__init__.py` or the release fails
before it builds anything, because a version on PyPI can never be reused.

**`v0` is a moving tag.** It tracks the latest `v0.x` release and is
force-updated to point at it. That is what makes
`uses: alokgorithm/ARKEXA@v0` work as the documented three-line adoption path
without asking people to edit a SHA on every release.

Moving it is automated: the `moving-tag` job in `release.yml` re-points `v0`
after a `v0.*` tag publishes successfully, using the GitHub API. It runs only
on success, because a moving tag advertising a release that never reached PyPI
sends `pip install` looking for something that is not there. Do not move it by
hand; if you must, it is:

```bash
git tag -f -a v0 -m "v0 moving tag" <commit> && git push -f origin v0
```

Note that `v0` selects the **scanner** version as well as the Action wrapper,
because the Action installs from its own checkout. Anyone on `@v0` therefore
gets whatever the newest `v0.x` release contains. That is the trade a moving
tag makes, and the README tells users how to opt out of it.

The release workflow triggers on `v*.*` rather than `v*` so that moving `v0`
does not look like a release attempt. When `v1` arrives it will need the same
treatment: a moving `v1`, and version tags that carry a dot.
