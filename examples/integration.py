#!/usr/bin/env python3
"""End-to-end: sentinel-policy decides, agentledger proves, repo-warden scopes.

This shows the four governance tools composing into one accountable path. Install
the suite packages first, then run it:

    pip install -e ../sentinel-policy -e ../agentledger -e ../repo-warden
    python examples/integration.py
"""

from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from repo_warden import Action, Store as WardenStore, Warden
from sentinel_policy import Policy


def main() -> None:
    # 1. An org governance policy, expressed against the SENTINEL doctrine.
    policy = Policy.from_dict({
        "name": "prod-controls",
        "default": "deny",
        "rules": [
            {"id": "reads-ok", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*"}},
            {"id": "gate-prod-deploy", "doctrine": "S3", "effect": "require_approval",
             "tier": "high", "match": {"action": "deploy", "params.env": {"eq": "prod"}}},
        ],
    })

    # 2. Wire that policy into agentledger's gate: every decision is now signed
    #    and hash-chained as it's made.
    gate = PolicyGate(default_allow=False).use(policy.as_gate_evaluator(defer_on_default=False))
    rec = Recorder(gate=gate)

    print(f"signing: {rec.signer.algorithm}\n")

    allowed, e1 = rec.submit("alice", "read.logs", {"lines": 100})
    print(f"[{e1.seq}] alice read.logs       -> allowed={allowed.allowed} ({allowed.rule})")

    denied, e2 = rec.submit("mallory", "deploy", {"env": "prod"})
    print(f"[{e2.seq}] mallory deploy(prod)  -> allowed={denied.allowed} ({denied.rule})")

    # 3. repo-warden scopes the actual git operation the allowed directive leads to.
    ws = WardenStore()
    token, _ = ws.issue_token("alice", {"branch:push"}, "acme/*")
    warden = Warden(ws)
    authz = warden.authorize(token, Action("push", "acme/api", "feature/x"))
    out = rec.record_outcome(e1.seq, "agent:dev", "git-push",
                             {"repo": "acme/api", "branch": "feature/x",
                              "allowed": authz.allowed, "rule": authz.rule})
    print(f"[{out.seq}] git push (feature/x) -> allowed={authz.allowed} ({authz.rule})")

    # 4. Prove the whole thing — locally and as an offline evidence bundle.
    ok, broken = rec.verify()
    bundle = rec.export_evidence()
    ok_offline, _ = verify_bundle(bundle)
    print(f"\nledger intact: {ok} (broken={broken})")
    print(f"evidence bundle verifies offline: {ok_offline} "
          f"({bundle['entry_count']} entries, head {bundle['head_hash'][:12]}…)")


if __name__ == "__main__":
    main()
