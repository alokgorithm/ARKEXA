"""Regenerate docs/rules/ARK00N.md from the rule registry and the fixtures.

Rule documentation that is written by hand drifts from the rule. This reads the
summary, the severity, the OWASP mapping and the explanation straight out of
the registry, and pulls the worked examples from the same fixtures the tests
run against, so a doc can never describe a rule that no longer exists.

    python tools/gen_rule_docs.py          write the files
    python tools/gen_rule_docs.py --check  fail if they are out of date
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from arkexa.registry import all_rules  # noqa: E402

DOCS = ROOT / "docs" / "rules"
FIXTURES = ROOT / "tests" / "fixtures"

HEADER = """# {id} {name}

|  |  |
|---|---|
| Severity | {severity} |
| OWASP Agentic Top 10 (2026) | {owasp} |
| Introduced in | v0.1 |

{summary}.

{explanation}
"""

EXAMPLE = """
## Reported

```yaml
{vulnerable}```

## Not reported

```yaml
{safe}```

Both files live in [`tests/fixtures`](../../tests/fixtures) and are checked on
every run, so the safe one is a promise, not a claim.
"""

FOOTER = """
## Reachability

This rule, like every other, is reported only when the job it lives in can be
triggered by the level you asked for. By default that means `external`: any
GitHub account. Add `--reachability all` to see findings that need write
access to reach.

## Suppressing it

```yaml
# .arkexa.yml
ignore:
  - rule: {id}
    path: .github/workflows/example.yml
    reason: why this one is acceptable
```

A `reason` is required. An ignore without one is reported and not applied.
"""


def read_fixture(name: str) -> str | None:
    path = FIXTURES / name
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def render(rule) -> str:
    body = HEADER.format(
        id=rule.id,
        name=f"`{rule.name}`",
        severity=rule.severity,
        owasp=rule.owasp,
        summary=rule.summary,
        explanation=rule.explanation,
    )
    vulnerable = read_fixture(f"{rule.id.lower()}_vulnerable.yml")
    safe = read_fixture(f"{rule.id.lower()}_safe.yml")
    if vulnerable and safe:
        body += EXAMPLE.format(vulnerable=vulnerable, safe=safe)
    body += FOOTER.format(id=rule.id)
    return body


def main(argv: list[str]) -> int:
    check = "--check" in argv
    DOCS.mkdir(parents=True, exist_ok=True)
    stale: list[str] = []

    for rule in all_rules():
        target = DOCS / f"{rule.id}.md"
        content = render(rule)
        if check:
            current = target.read_text(encoding="utf-8") if target.is_file() else ""
            if current != content:
                stale.append(target.name)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")

    if check and stale:
        print("out of date: " + ", ".join(stale))
        print("run: python tools/gen_rule_docs.py")
        return 1
    if not check:
        print(f"wrote {len(all_rules())} rule documents to {DOCS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
