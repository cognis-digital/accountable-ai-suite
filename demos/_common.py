"""Shared helpers for the suite demo scenarios.

The Accountable AI Engineering suite is an umbrella over five tools that each
ship in their own repo:

    sentinel-policy   the governance doctrine + decision engine
    agentledger       the signed, hash-chained flight recorder
    repo-warden       git access governance (device-flow, scoped tokens)
    codegraph-mcp     the no-train code knowledge graph served over MCP
    cyclework         the inspectable propose -> check -> revise loop

These demos exercise the *real* APIs of those packages. They resolve the
packages in this order, all fully offline:

  1. whatever is installed in the environment (what CI does), else
  2. sibling source checkouts next to this repo (the common dev layout:
     ../agentledger, ../sentinel-policy, ...).

A package that can't be resolved is reported as MISSING and the demo skips the
part that needs it rather than crashing -- so every scenario runs and exits 0
on a machine that only has some of the suite checked out.
"""
from __future__ import annotations

import importlib
import os
import sys

# allow `python demos/xx.py` from anywhere
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# the parent directory that (in the standard dev layout) holds the sibling repos
_SUITE_PARENT = os.path.dirname(REPO_ROOT)

# map: importable module name -> sibling checkout directory name
_SIBLINGS = {
    "agentledger": "agentledger",
    "sentinel_policy": "sentinel-policy",
    "repo_warden": "repo-warden",
    "codegraph": "codegraph-mcp",
    "cyclework": "cyclework",
}


def _ok(module: str) -> bool:
    """Import the module and (for codegraph) confirm it's the suite's package.

    The name `codegraph` is also used by unrelated PyPI packages, so a bare
    import isn't enough -- we check that the suite's symbols are present.
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
    """Make `module` importable from a sibling checkout if it isn't already."""
    if _ok(module):
        return True
    checkout = os.path.join(_SUITE_PARENT, _SIBLINGS.get(module, module))
    if os.path.isdir(checkout) and checkout not in sys.path:
        sys.path.insert(0, checkout)
    # drop any already-imported wrong module so the sibling can be picked up
    for cached in [m for m in list(sys.modules) if m == module or m.startswith(module + ".")]:
        del sys.modules[cached]
    return _ok(module)


# resolve everything up front so demos can introspect availability
AVAILABLE = {mod: _ensure_on_path(mod) for mod in _SIBLINGS}


def require(*modules: str) -> bool:
    """True only if every named module resolved; prints a friendly skip note."""
    missing = [m for m in modules if not AVAILABLE.get(m)]
    if missing:
        print(f"\n   (skipping: {', '.join(missing)} not installed and no sibling "
              f"checkout found next to this repo)")
        return False
    return True


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def suite_status() -> None:
    """Print which suite tools resolved, for the header of every demo."""
    names = {
        "sentinel_policy": "sentinel-policy",
        "agentledger": "agentledger",
        "repo_warden": "repo-warden",
        "codegraph": "codegraph-mcp",
        "cyclework": "cyclework",
    }
    parts = [f"{'ok ' if AVAILABLE[m] else 'MISSING '}{label}"
             for m, label in names.items()]
    print("   suite: " + "  |  ".join(parts))
