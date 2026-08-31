"""`.arkexa.yml` - ignores, each of which has to say why.

An ignore without a reason is how a scanner quietly stops working. Every entry
here needs a `reason`, and entries missing one are reported rather than obeyed.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_NAMES = (".arkexa.yml", ".arkexa.yaml")


@dataclass
class Ignore:
    rule: str = "*"
    path: str = "*"
    reason: str = ""

    def matches(self, rule_id: str, workflow_path: str) -> bool:
        return fnmatch.fnmatch(rule_id, self.rule) and fnmatch.fnmatch(
            workflow_path, self.path
        )


@dataclass
class Config:
    ignores: list[Ignore] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    path: Path | None = None

    def is_ignored(self, rule_id: str, workflow_path: str) -> Ignore | None:
        for ignore in self.ignores:
            if ignore.matches(rule_id, workflow_path):
                return ignore
        return None


def _coerce(entry: Any, index: int, problems: list[str]) -> Ignore | None:
    if not isinstance(entry, dict):
        problems.append(f"ignore #{index + 1} is not a mapping; skipped")
        return None
    reason = str(entry.get("reason", "")).strip()
    rule_id = str(entry.get("rule", "*"))
    if not reason:
        problems.append(
            f"ignore #{index + 1} ({rule_id}) has no reason and was not applied"
        )
        return None
    return Ignore(rule=rule_id, path=str(entry.get("path", "*")), reason=reason)


def load(root: Path) -> Config:
    for name in CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            problems: list[str] = []
            ignores: list[Ignore] = []
            raw = data.get("ignore", []) if isinstance(data, dict) else []
            if isinstance(raw, list):
                for index, entry in enumerate(raw):
                    parsed = _coerce(entry, index, problems)
                    if parsed is not None:
                        ignores.append(parsed)
            return Config(ignores=ignores, problems=problems, path=candidate)
    return Config()
