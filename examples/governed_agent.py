#!/usr/bin/env python3
"""A reference *governed agent* — every action flows through the suite.

This is the shape we want teams to copy: an agent that cannot take an action
except through the accountable path. It doesn't call a git remote or a policy
engine directly; it calls ``Orchestrator.act(...)`` and the suite decides,
records, scopes, and (optionally) grounds every step.

The agent here is a tiny "code-fix" worker: it reads logs, grounds a change
against the code graph, pushes to a feature branch, is refused a push to a
protected branch, and is refused an exfiltration attempt. Each is one
``act()`` call; the resulting ledger is a signed, hash-chained, offline-
verifiable record of exactly what the agent was and wasn't allowed to do.

Run it:

    pip install -e ../sentinel-policy -e ../agentledger -e ../repo-warden
    PYTHONUTF8=1 python examples/governed_agent.py

It exits 0 whether or not every optional tool is installed; missing tools are
reported and their step is scoped down rather than crashing.
"""
from __future__ import annotations

import os
import sys

# make the capstone package importable when run straight from the repo
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from accountable_suite import Orchestrator, build_report, resolve  # noqa: E402
from accountable_suite.orchestrator import _sample_graph_store  # noqa: E402


class GovernedAgent:
    """An agent that can only act through the accountable orchestrator."""

    def __init__(self, orchestrator: Orchestrator, *, identity: str, token=None):
        self.orch = orchestrator
        self.identity = identity
        self.token = token
        self.log = []

    def do(self, action: str, params: dict, *, ground_symbol=None):
        outcome = self.orch.act(actor=self.identity, action=action,
                                params=params, token=self.token,
                                ground_symbol=ground_symbol)
        self.log.append(outcome)
        status = "ALLOWED" if outcome.allowed else "REFUSED"
        extra = ""
        if outcome.warden_rule:
            extra = f"  [warden:{outcome.warden_rule}]"
        if outcome.graph_facts and outcome.graph_facts.get("found"):
            gf = outcome.graph_facts
            extra += f"  [grounded:{gf['symbol']} blast={gf['impacted_count']}]"
        print(f"  {status:<8} {action:<12} {params}  "
              f"-> policy={outcome.policy_rule}{extra}")
        return outcome


def build_agent():
    av = resolve.availability()

    policy = None
    if av.has("sentinel_policy"):
        from sentinel_policy import Policy
        policy = Policy.from_dict({
            "name": "code-fix-agent", "default": "deny",
            "rules": [
                {"id": "read-logs", "doctrine": "S2", "effect": "allow",
                 "match": {"action": "read.*"}},
                {"id": "feature-push", "doctrine": "S4", "effect": "allow",
                 "match": {"action": "push"}},
                {"id": "gate-deploy", "doctrine": "S3", "effect": "require_approval",
                 "tier": "high", "match": {"action": "deploy"}},
                {"id": "no-exfil", "doctrine": "S6", "effect": "deny",
                 "match": {"action": "exfiltrate"}},
            ],
        })

    warden_store = None
    warden_audit = None
    token = None
    if av.has("repo_warden"):
        from repo_warden import AuditLog, Store
        warden_store = Store()
        warden_audit = AuditLog(warden_store)
        token, _ = warden_store.issue_token("agent:code-fix",
                                            {"branch:push"}, "acme/*")

    graph_store = _sample_graph_store() if av.has("codegraph") else None

    orch = Orchestrator(policy=policy, warden_store=warden_store,
                        graph_store=graph_store)
    if warden_store is not None:
        orch.warden.audit = warden_audit  # so the report can see the events

    agent = GovernedAgent(orch, identity="agent:code-fix", token=token)
    return agent, policy, warden_audit, graph_store


def main() -> None:
    print("=" * 70)
    print("  Reference governed agent — every action through the accountable path")
    print("=" * 70)
    av = resolve.availability()
    print("  tools: " + ", ".join(
        f"{av.label(m)}={'ok' if p else 'MISSING'}" for m, p in av.as_dict().items()))
    if not av.has("agentledger"):
        print("\n  agentledger is required for the orchestrator; not resolvable. "
              "Skipping (exit 0).")
        return

    agent, policy, warden_audit, graph_store = build_agent()

    print("\nThe agent takes four actions; the suite governs each one:\n")
    agent.do("read.logs", {"service": "api", "lines": 200})
    agent.do("push", {"repo": "acme/api", "branch": "feature/fix-123"},
             ground_symbol="loadUser")
    agent.do("push", {"repo": "acme/api", "branch": "main"})       # protected
    agent.do("exfiltrate", {"to": "pastebin.example"})              # denied by S6

    ok, broken = agent.orch.verify()
    bundle = agent.orch.export_evidence()
    print(f"\nEvery step recorded. Ledger verifies={ok} (broken={broken}); "
          f"{bundle['entry_count']} signed entries, "
          f"head {bundle['head_hash'][:12]}…")

    rpt = build_report(title="Governed Agent — Session Report",
                       policy=policy, recorder=agent.orch.recorder,
                       warden_audit=warden_audit, graph_store=graph_store)
    print(f"Governance maturity: {rpt.scorecard.level} "
          f"({rpt.scorecard.overall:.0f}/100); {len(rpt.findings)} finding(s).")
    print("\nThe agent could not step outside the path: no unsigned action, no "
          "unscoped push, and every refusal is on the record.")


if __name__ == "__main__":
    main()
