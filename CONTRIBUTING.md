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
