"""Helpers shared by the tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arkexa.engine import scan  # noqa: E402


def scan_fixture(name: str):
    """Scan one fixture and return every finding, reachable or not."""
    return scan(FIXTURES / name).findings


def rule_ids(findings) -> set[str]:
    return {finding.rule for finding in findings}
