"""Line-preserving YAML loading.

Two things separate this from ``yaml.safe_load``:

1. Every mapping, sequence and scalar remembers the line it came from, so a
   finding can point at the exact key that caused it.
2. ``on`` stays the string ``"on"``. YAML 1.1 resolves ``on``/``off``/``yes``/
   ``no`` to booleans, which turns every workflow's trigger block into a key
   named ``True``. GitHub does not read workflows that way, so neither do we:
   only ``true`` and ``false`` are booleans here.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

__all__ = ["LineDict", "LineList", "LineStr", "load_yaml", "line_of"]


class LineDict(dict):
    """A mapping that knows where it and each of its keys were written."""

    line: int = 0
    key_lines: dict[str, int]

    def key_line(self, key: str, default: int | None = None) -> int:
        return self.key_lines.get(key, default if default is not None else self.line)


class LineList(list):
    line: int = 0


class LineStr(str):
    line: int = 0


class LineLoader(yaml.SafeLoader):
    """SafeLoader that records positions and does not invent booleans."""


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    data = LineDict()
    data.line = node.start_mark.line + 1
    data.key_lines = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        data[key] = loader.construct_object(value_node, deep=True)
        if isinstance(key, str):
            data.key_lines[key] = key_node.start_mark.line + 1
    return data


def _construct_sequence(loader: LineLoader, node: yaml.SequenceNode) -> LineList:
    data = LineList(loader.construct_object(child, deep=True) for child in node.value)
    data.line = node.start_mark.line + 1
    return data


def _construct_str(loader: LineLoader, node: yaml.ScalarNode) -> LineStr:
    data = LineStr(loader.construct_scalar(node))
    data.line = node.start_mark.line + 1
    return data


LineLoader.add_constructor("tag:yaml.org,2002:map", _construct_mapping)
LineLoader.add_constructor("tag:yaml.org,2002:seq", _construct_sequence)
LineLoader.add_constructor("tag:yaml.org,2002:str", _construct_str)

# Drop YAML 1.1's generous boolean resolver and put back a strict one, so that
# `on:`, `yes:` and `no:` survive as the strings the workflow author wrote.
LineLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
LineLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


class WorkflowParseError(Exception):
    """A workflow file could not be read as YAML."""


def load_yaml(text: str) -> Any:
    try:
        return yaml.load(text, Loader=LineLoader)
    except yaml.YAMLError as exc:  # pragma: no cover - message shape only
        raise WorkflowParseError(str(exc)) from exc


def line_of(value: Any, default: int = 0) -> int:
    """Best-effort line number for anything the loader produced."""
    return getattr(value, "line", default) or default
