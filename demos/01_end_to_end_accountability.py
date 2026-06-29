"""Scenario 1 - CTOs & engineering leaders: the whole accountable path.

The promise of the suite is one sentence: from an operator's intent to an
agent's action against your code, every step is decided by a rule, proved by a
signed record, and scoped to least authority -- and you can hand the result to
an auditor as a file they verify offline.

This demo plays that path straight through, against the *real* APIs:

    sentinel-policy decides  ->  agentledger proves  ->  repo-warden scopes
                                     |
                                     +-> offline-verifiable evidence bundle

It is the suite's headline claim, executed rather than asserted.
"""
from _common import rule, require, suite_status


def main() -> None:
    rule("END-TO-END ACCOUNTABILITY  -  decide, prove, scope, then verify offline")
    suite_status()
    if not require("sentinel_policy", "agentledger", "repo_warden"):
        return

    from sentinel_policy import Policy
    from agentledger import PolicyGate, Recorder
    from agentledger.evidence import verify_bundle
    from repo_warden import Action, Store as WardenStore, Warden

    # 1. The org's governance, written against the SENTINEL doctrine. Each rule
    #    cites the doctrine principle it serves (S2 least authority, S3 gated
    #    escalation) so any decision traces back to a stated principle.
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
    problems = policy.validate()
    print(f"\n1) policy '{policy.name}' loaded, default={policy.default.value}, "
          f"validation problems={problems or 'none'}")

    # 2. agentledger records every directive as it is decided -- signed and
    #    hash-chained. The policy is the gate's first evaluator.
    gate = PolicyGate(default_allow=False).use(
        policy.as_gate_evaluator(defer_on_default=False))
    rec = Recorder(gate=gate)
    print(f"2) flight recorder armed; signing algorithm = {rec.signer.algorithm}")

    print("\n   directives submitted to the gate:")
    allowed, e1 = rec.submit("alice", "read.logs", {"lines": 100})
    print(f"     [{e1.seq}] alice  read.logs      -> allowed={allowed.allowed:<5} "
          f"rule={allowed.rule} (doctrine {allowed.doctrine})")
    denied, e2 = rec.submit("mallory", "deploy", {"env": "prod"})
    print(f"     [{e2.seq}] mallory deploy(prod)  -> allowed={denied.allowed:<5} "
          f"rule={denied.rule} (doctrine {denied.doctrine}) <- gated, not silently dropped")

    # 3. repo-warden scopes the actual git operation the allowed directive leads
    #    to: a token scoped to acme/* with branch:push, exercised on a feature
    #    branch. The outcome is recorded back onto the originating directive.
    ws = WardenStore()
    token, info = ws.issue_token("agent:dev", {"branch:push"}, "acme/*")
    warden = Warden(ws)
    authz = warden.authorize(token, Action("push", "acme/api", "feature/x"))
    out = rec.record_outcome(e1.seq, "agent:dev", "git-push",
                             {"repo": "acme/api", "branch": "feature/x",
                              "allowed": authz.allowed, "rule": authz.rule})
    print(f"\n3) warden token id={info.id} namespace='{info.namespace}' "
          f"scopes={sorted(info.scopes)}")
    print(f"     [{out.seq}] git push acme/api:feature/x -> allowed={authz.allowed} "
          f"(rule={authz.rule})")

    # 4. Prove the whole thing, then export a bundle an outsider verifies with
    #    no access to our systems.
    ok, broken = rec.verify()
    bundle = rec.export_evidence()
    ok_offline, _ = verify_bundle(bundle)
    print(f"\n4) ledger intact={ok} (first_broken={broken})")
    print(f"   evidence bundle: {bundle['entry_count']} entries, "
          f"head {bundle['head_hash'][:12]}..., verifies offline={ok_offline}")

    print("\nA policy decided, the ledger proved, the warden scoped -- and the "
          "evidence stands on its own.")


if __name__ == "__main__":
    main()
