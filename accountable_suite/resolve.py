"""Resolve the five suite tools — from the environment, then sibling checkouts.

The suite is an umbrella over five packages that each ship in their own repo.
Nothing here vendors them; this module locates whichever ones are present and
reports the rest as missing, so every capstone feature degrades gracefully on a
machine (or a CI job) that only has some of the suite installed.

Resolution order, all fully offline:

  1. whatever is importable in the current environment, else
  2. a sibling source checkout next to this repo (the common dev layout:
     ``../agentledger``, ``../sentinel-policy``, ...).

This mirrors what ``demos/_common.py`` does for the standalone demo scripts, but
as an importable, testable API the rest of the package (orchestrator, reports,
scorecard, CLI) builds on.
"""
from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from typing import Dict, Optional

# this file lives at <repo>/accountable_suite/resolve.py
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_PKG_DIR)
SUITE_PARENT = os.path.dirname(REPO_ROOT)

# importable module name -> (sibling checkout dir name, human label)
TOOLS: Dict[str, tuple] = {
    "sentinel_policy": ("sentinel-policy", "sentinel-policy"),
    "agentledger": ("agentledger", "agentledger"),
    "repo_warden": ("repo-warden", "repo-warden"),
    "codegraph": ("codegraph-mcp", "codegraph-mcp"),
    "cyclework": ("cyclework", "cyclework"),
}


def _importable(module: str) -> bool:
    """Import ``module`` and, for codegraph, confirm it's the suite's package.

    The bare name ``codegraph`` is also published by unrelated projects, so a
    plain import is not enough — we check the suite's symbols are present.
    """
    try:
        importlib.import_module(module)
    except Exception:
        return False
    if module == "codegraph":
        try:
            importlib.import_module("codegraph.graph").Store  # noqa: B018
            importlib.import_module("codegraph.indexer").index_path  # noqa: B018
        except Exception:
            return False
    return True


def _ensure_on_path(module: str) -> bool:
    """Make ``module`` importable from a sibling checkout if it isn't already."""
    if _importable(module):
        return True
    checkout_dir, _ = TOOLS.get(module, (module, module))
    checkout = os.path.join(SUITE_PARENT, checkout_dir)
    if os.path.isdir(checkout) and checkout not in sys.path:
        sys.path.insert(0, checkout)
    # drop any partially/wrongly imported module so the sibling can be picked up
    for cached in [m for m in list(sys.modules)
                   if m == module or m.startswith(module + ".")]:
        del sys.modules[cached]
    return _importable(module)


@dataclass(frozen=True)
class Availability:
    """Which suite tools resolved in this environment."""
    present: Dict[str, bool]

    def __getitem__(self, module: str) -> bool:
        return self.present.get(module, False)

    def has(self, *modules: str) -> bool:
        return all(self.present.get(m, False) for m in modules)

    def missing(self, *modules: str) -> list:
        want = modules or tuple(self.present)
        return [m for m in want if not self.present.get(m, False)]

    def label(self, module: str) -> str:
        return TOOLS.get(module, (module, module))[1]

    def as_dict(self) -> dict:
        return dict(self.present)


_cache: Optional[Availability] = None


def availability(refresh: bool = False) -> Availability:
    """Resolve every suite tool (once, cached) and report presence."""
    global _cache
    if _cache is None or refresh:
        _cache = Availability({m: _ensure_on_path(m) for m in TOOLS})
    return _cache


def require(*modules: str) -> bool:
    """True only if every named module resolved (resolving them if needed)."""
    return availability().has(*modules)
