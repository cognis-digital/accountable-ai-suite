"""The end-to-end accountability orchestrator.

The suite's headline claim is that the five tools compose into a single
accountable path: a policy *decides*, the ledger *proves*, the warden *scopes*,
the graph *informs*, and the whole thing exports as evidence a third party can
verify offline. The demos show that path by hand; this module makes it *one
call*.

    orch = Orchestrator(policy=my_policy, warden_store=ws)
    outcome = orch.act(
        actor="agent:dev",
        action="push",
        params={"repo": "acme/api", "branch": "feature/x"},
        token=token,
    )

``act()`` runs, in order:

  1. sentinel-policy evaluates the directive against the SENTINEL doctrine
     (allow / deny / require-approval), citing the rule it serves.
  2. agentledger records the *directive and its decision*, signed and
     hash-chained — allowed or not, so refusals are provable too (S7).
  3. if allowed and the action is a git op, repo-warden authorizes the scoped
     operation against a presented token; the warden's own decision is recorded
     as an outcome on the originating directive.
  4. the result is a fully typed ``Outcome`` — and at any point you can
     ``export_evidence()`` a self-contained bundle that verifies with no access
     to the running system.

Everything is real API of the sibling packages; nothing is stubbed. It works
whenever agentledger + sentinel-policy are resolvable, and folds in repo-warden
scoping when that is present too. It never raises on a governance *decision*
(a deny is a normal, recorded outcome) — it only raises on genuine misuse.
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import resolve

# git operations the orchestrator knows how to scope through repo-warden
_GIT_OPS = {"push", "read", "delete"}


@dataclass
class Outcome:
    """A fully accountable record of one orchestrated action."""
    actor: str
    action: str
    params: Dict[str, Any]
    allowed: bool                      # policy allowed AND (if git) warden allowed
    policy_allowed: bool
    policy_rule: str
    policy_doctrine: Optional[str]
    policy_effect: str
    directive_seq: int
    outcome_seq: Optional[int] = None
    # git scoping (only set when the action was a scoped git op)
    warden_allowed: Optional[bool] = None
    warden_rule: Optional[str] = None
    warden_reason: str = ""
    graph_facts: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "actor": self.actor,
            "action": self.action,
            "params": self.params,
            "allowed": self.allowed,
            "policy": {
                "allowed": self.policy_allowed,
                "rule": self.policy_rule,
                "doctrine": self.policy_doctrine,
                "effect": self.policy_effect,
            },
            "warden": None if self.warden_allowed is None else {
                "allowed": self.warden_allowed,
                "rule": self.warden_rule,
                "reason": self.warden_reason,
            },
            "directive_seq": self.directive_seq,
            "outcome_seq": self.outcome_seq,
            "graph_facts": self.graph_facts,
            "notes": self.notes,
        }


class Orchestrator:
    """Wire policy -> ledger -> warden -> evidence into one accountable call.

    Parameters
    ----------
    policy:
        A ``sentinel_policy.Policy`` (or anything exposing
        ``as_gate_evaluator``). If omitted, a permissive default gate is used
        and every directive is recorded but not doctrine-gated.
    warden_store:
        A ``repo_warden.Store`` used to authorize git operations. If omitted (or
        repo-warden isn't installed), git actions are recorded by the ledger but
        not scoped, and a note explains that.
    branch_policy:
        Optional ``repo_warden.BranchPolicy`` controlling protected branches.
    signer:
        Optional agentledger ``Signer`` (defaults to Ed25519 when available).
    db_path:
        Ledger backing store (default in-memory).
    graph_store:
        Optional ``codegraph.graph.Store`` used to attach grounding facts (blast
        radius) to code-touching actions.
    """

    def __init__(self, *, policy: Any = None, warden_store: Any = None,
                 branch_policy: Any = None, signer: Any = None,
                 db_path: str = ":memory:", graph_store: Any = None):
        av = resolve.availability()
        if not av.has("agentledger"):
            raise RuntimeError(
                "agentledger is required for the orchestrator but is not "
                "resolvable (install it or check out ../agentledger)")

        from agentledger import PolicyGate, Recorder

        gate = PolicyGate(default_allow=policy is None)
        if policy is not None:
            # the org doctrine gets first say, and always decides (no deferral)
            gate.use(policy.as_gate_evaluator(defer_on_default=False))
        self.policy = policy
        self.recorder = Recorder(gate=gate, signer=signer, db_path=db_path)

        self.warden = None
        self.warden_store = warden_store
        if warden_store is not None and av.has("repo_warden"):
            from repo_warden import Warden
            kwargs = {}
            if branch_policy is not None:
                kwargs["policy"] = branch_policy
            self.warden = Warden(warden_store, **kwargs)

        self.graph_store = graph_store if av.has("codegraph") else None

    # ---- introspection ---------------------------------------------------
    @property
    def signer(self):
        return self.recorder.signer

    def entries(self) -> list:
        return self.recorder.entries()

    # ---- the one call ----------------------------------------------------
    def act(self, *, actor: str, action: str,
            params: Optional[Dict[str, Any]] = None,
            token: Optional[str] = None,
            ground_symbol: Optional[str] = None) -> Outcome:
        """Run one directive through the whole accountable path.

        ``token`` is a repo-warden token used to scope a git action. For a git
        op, ``params`` should carry at least ``repo`` (and usually ``branch``);
        ``force`` and ``paths`` are honored if present. ``ground_symbol``, when a
        code graph is attached, asks the graph for that symbol's blast radius and
        records it as grounding on the outcome.
        """
        params = dict(params or {})
        notes: List[str] = []

        # 1) policy decides; 2) the decision is signed + hash-chained as recorded
        decision, directive = self.recorder.submit(actor, action, params)
        policy_doctrine = getattr(decision, "doctrine", None)
        policy_effect = getattr(decision, "effect", None)
        policy_effect = policy_effect.value if hasattr(policy_effect, "value") else (
            "allow" if decision.allowed else "deny")

        outcome = Outcome(
            actor=actor, action=action, params=params,
            allowed=decision.allowed,
            policy_allowed=decision.allowed,
            policy_rule=decision.rule,
            policy_doctrine=policy_doctrine,
            policy_effect=policy_effect,
            directive_seq=directive.seq,
            notes=notes,
        )

        if not decision.allowed:
            notes.append(f"policy refused ({policy_effect}); recorded as a "
                         "provable refusal (SENTINEL S7), no action taken")
            return outcome

        # optional: ground a code-touching action against the no-train graph
        if ground_symbol and self.graph_store is not None:
            outcome.graph_facts = self._ground(ground_symbol)

        # 3) if this is a git op, repo-warden scopes it
        is_git = action in _GIT_OPS
        if is_git:
            outcome.warden_allowed, outcome.warden_rule, outcome.warden_reason = \
                self._scope_git(action, params, token, notes)
            outcome.allowed = decision.allowed and bool(outcome.warden_allowed)
            status = "git-op-allowed" if outcome.warden_allowed else "git-op-denied"
            detail = {
                "repo": params.get("repo"), "branch": params.get("branch"),
                "warden_allowed": outcome.warden_allowed,
                "warden_rule": outcome.warden_rule,
                "warden_reason": outcome.warden_reason,
            }
        else:
            status = "executed"
            detail = {"result": "ok"}

        # record the outcome back onto the originating directive
        out_entry = self.recorder.record_outcome(directive.seq, actor, status, detail)
        outcome.outcome_seq = out_entry.seq
        return outcome

    # ---- internals -------------------------------------------------------
    def _scope_git(self, action: str, params: dict, token: Optional[str],
                   notes: List[str]):
        if self.warden is None:
            notes.append("repo-warden not attached; git op recorded but not "
                         "scoped (attach a warden_store to enforce S2)")
            return True, "unscoped", "no warden configured"
        if not token:
            notes.append("no token presented for a git op; warden denies (S1)")
            return False, "auth", "no token presented"
        from repo_warden import Action
        act = Action(
            op=action,
            repo=params.get("repo", ""),
            branch=params.get("branch"),
            force=bool(params.get("force", False)),
            paths=tuple(params.get("paths", ()) or ()),
        )
        d = self.warden.authorize(token, act)
        return d.allowed, d.rule, d.reason

    def _ground(self, symbol_name: str) -> Optional[dict]:
        hits = self.graph_store.search_symbols(symbol_name, None, 1)
        if not hits:
            return {"symbol": symbol_name, "found": False}
        sym = hits[0]
        blast = self.graph_store.impact(sym.id)
        return {
            "symbol": sym.name, "found": True, "lang": sym.lang,
            "location": f"{sym.path}:{sym.start_line}",
            "impacted_count": blast["impacted_count"],
        }

    # ---- proof -----------------------------------------------------------
    def verify(self) -> tuple:
        """Replay the ledger's hash chain + signatures. Returns (ok, broken)."""
        return self.recorder.verify()

    def export_evidence(self, path: Optional[str] = None) -> dict:
        """Export a self-contained, offline-verifiable evidence bundle."""
        return self.recorder.export_evidence(path)


def _sample_graph_store():
    """Best-effort: index codegraph-mcp's bundled sample repo, for demos/tests.

    Returns a codegraph Store, or None if codegraph or the sample isn't present.
    """
    av = resolve.availability()
    if not av.has("codegraph"):
        return None
    sample = os.path.join(resolve.SUITE_PARENT, "codegraph-mcp",
                          "examples", "sample_repo")
    if not os.path.isdir(sample):
        return None
    from codegraph.graph import Store
    from codegraph.indexer import index_path
    db = os.path.join(tempfile.mkdtemp(prefix="suite_orch_"), "graph.db")
    store = Store(db)
    index_path(store, sample)
    return store
