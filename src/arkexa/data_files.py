"""Loading of the YAML data files that drive detection."""

from __future__ import annotations

import functools
from importlib import resources
from typing import Any

import yaml


@functools.lru_cache(maxsize=None)
def load(name: str) -> dict[str, Any]:
    text = resources.files("arkexa.data").joinpath(f"{name}.yml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def agents() -> dict[str, Any]:
    return load("agents")


def untrusted() -> dict[str, Any]:
    return load("untrusted")


def guards() -> dict[str, Any]:
    return load("guards")
