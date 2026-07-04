"""Scenario 6 - Platform/AppSec: the whole accountable path in one call.

Demos 1-5 show the tools composing by hand. The capstone's ``Orchestrator``
collapses that into a single ``act()`` call: policy decides, the ledger signs
and chains the decision, repo-warden scopes the git op, and the code graph
grounds the change — all behind one method, with a typed ``Outcome`` back.

This runs a governed agent's four actions through ``act()`` and then proves the
whole session with one offline-verifiable evidence bundle.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import rule, require, suite_status  # noqa: E402


def main() -> None:
    rule("ORCHESTRATED PATH  -  policy -> ledger -> warden -> evidence, in one call")
    suite_status()
    if not require("agentledger"):
        return

    from accountable_suite import Orchestrator, resolve
    from accountable_suite.orchestrator import _sample_graph_store

    av = resolve.availability()
    policy = None
    if av.has("sentinel_policy"):
        from sentinel_policy import Policy
        policy = Policy.from_dict({
            "name": "prod-controls", "default": "deny",
            "rules": [
                {"id": "reads-ok", "doctrine": "S2", "effect": "allow",
                 "match": {"action": "read.*"}},
                {"id": "audit-writes", "doctrine": "S4", "effect": "allow",
                 "match": {"action": "push"}},
                {"id": "no-exfil", "doctrine": "S6", "effect": "deny",
                 "match": {"action": "exfiltrate"}},
            ],
        })

    warden_store = None
    token = None
    if av.has("repo_warden"):
        from repo_warden import Store
        warden_store = Store()
        token, _ = warden_store.issue_token("agent:dev", {"branch:push"}, "acme/*")

    graph_store = _sample_graph_store() if av.has("codegraph") else None

    orch = Orchestrator(policy=policy, warden_store=warden_store,
                        graph_store=graph_store)
    print(f"\norchestrator armed; signing {orch.signer.algorithm}"
          + ("" if policy else "  (no policy: permissive gate)")
          + ("" if warden_store else "  (no warden: git ops recorded, not scoped)"))

    print("\n   one act() per agent action:")
    for actor, action, params, ground in [
        ("alice", "read.logs", {"lines": 100}, None),
        ("agent:dev", "push", {"repo": "acme/api", "branch": "feature/x"}, "loadUser"),
        ("agent:dev", "push", {"repo": "acme/api", "branch": "main"}, None),
        ("mallory", "exfiltrate", {"to": "external"}, None),
    ]:
        oc = orch.act(actor=actor, action=action, params=params,
                      token=token, ground_symbol=ground)
        extra = f" warden={oc.warden_rule}" if oc.warden_rule else ""
        if oc.graph_facts and oc.graph_facts.get("found"):
            extra += f" grounded(blast={oc.graph_facts['impacted_count']})"
        print(f"     {actor:<10} {action:<12} -> allowed={oc.allowed!s:<5} "
              f"policy={oc.policy_rule}{extra}")

    ok, broken = orch.verify()
    bundle = orch.export_evidence()
    print(f"\n   ledger verifies={ok} (broken={broken}); "
          f"{bundle['entry_count']} signed entries, head {bundle['head_hash'][:12]}…")
    print("\nOne call per action, one bundle for the auditor — the path is the API.")


if __name__ == "__main__":
    main()
