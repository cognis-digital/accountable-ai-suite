"""Version-tolerant shims for the sibling tools.

The suite tools evolve independently, and a given environment (notably CI, which
installs the *published* releases) may have an older version than a local
sibling checkout. Rather than pin to the newest API, the capstone feature-detects
and falls back, so it works against whatever is installed.

Everything here is pure helper logic over public attributes; nothing reaches
into a tool's internals.
"""
from __future__ import annotations

from typing import Any, Optional, Sequence

# the SENTINEL doctrine is exactly seven rules (S1..S7)
_ALL_DOCTRINE = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]


def doctrine_coverage(policy: Any) -> dict:
    """Return a policy's doctrine coverage, using the native method if present.

    Older sentinel-policy releases don't ship ``Policy.doctrine_coverage``; this
    computes the same shape from ``policy.rules`` (each rule carries a
    ``.doctrine`` id) so the report/scorecard work either way.
    """
    native = getattr(policy, "doctrine_coverage", None)
    if callable(native):
        return native()
    cited = {getattr(r, "doctrine", None) for r in policy.rules}
    cited.discard(None)
    all_ids = set(_ALL_DOCTRINE)
    return {
        "covered": sorted(cited & all_ids),
        "uncovered": sorted(all_ids - cited),
        "by_rule": {r.id: getattr(r, "doctrine", None) for r in policy.rules},
        "uncited_rules": sorted(r.id for r in policy.rules
                                if not getattr(r, "doctrine", None)),
    }


def make_action(action_cls: Any, *, op: str, repo: str,
                branch: Optional[str] = None, force: bool = False,
                paths: Sequence[str] = ()) -> Any:
    """Construct a repo-warden ``Action`` across versions.

    Newer releases accept ``paths`` (for path-scoped write policy); older ones
    don't. Only pass ``paths`` when the dataclass actually declares it.
    """
    kwargs = {"op": op, "repo": repo, "branch": branch, "force": force}
    fields = getattr(action_cls, "__dataclass_fields__", {})
    if "paths" in fields and paths:
        kwargs["paths"] = tuple(paths)
    return action_cls(**kwargs)


def warden_supports_audit(warden_module: Any) -> bool:
    """True if this repo-warden ships the AuditLog + JSONL export surface."""
    return hasattr(warden_module, "AuditLog") and hasattr(warden_module, "to_jsonl")


def make_warden(warden_cls: Any, store: Any, *, policy: Any = None,
                audit: Any = None) -> Any:
    """Construct a Warden, passing ``audit=`` only if the version accepts it."""
    import inspect
    kwargs: dict = {}
    if policy is not None:
        kwargs["policy"] = policy
    try:
        params = inspect.signature(warden_cls.__init__).parameters
    except (TypeError, ValueError):
        params = {}
    if audit is not None and "audit" in params:
        kwargs["audit"] = audit
    return warden_cls(store, **kwargs)
