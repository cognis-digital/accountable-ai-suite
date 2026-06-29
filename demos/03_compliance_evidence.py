"""Scenario 3 - compliance & audit: approvals, key rotation, offline evidence.

A compliance reviewer wants three things a screenshot can't give them: that a
high-risk action got an independent second approval (S3), that rotating a
signing key didn't create a gap an attacker could hide in, and that the whole
record verifies months later with no access to your systems (S4). All three are
first-class in agentledger; this demo exercises them on the real API.
"""
from _common import rule, require, suite_status


def main() -> None:
    rule("COMPLIANCE EVIDENCE  -  m-of-n approval, key rotation, offline bundle")
    suite_status()
    if not require("sentinel_policy", "agentledger"):
        return

    from sentinel_policy import Policy
    from agentledger import PolicyGate, Recorder
    from agentledger.evidence import verify_bundle
    from agentledger.signing import new_signer

    # A policy that requires approval for the high-risk action (S3).
    policy = Policy.from_dict({
        "name": "change-control",
        "default": "allow",
        "rules": [
            {"id": "gate-migrations", "doctrine": "S3", "effect": "require_approval",
             "tier": "high", "match": {"action": "db.migrate"}},
        ],
    })
    gate = PolicyGate(default_allow=True).use(policy.as_gate_evaluator())
    rec = Recorder(gate=gate)

    # 1. S3 gated escalation: a high-tier directive needs an independent approval
    #    before it may proceed. require_approval is NOT allowed-to-run on its own.
    print("\nS3 gated escalation -- a high-risk directive needs a second authority:")
    decision, directive = rec.submit("agent:ops", "db.migrate", {"db": "billing"})
    print(f"   [{directive.seq}] db.migrate(billing) -> allowed={decision.allowed} "
          f"effect={decision.effect.value} (rule {decision.rule}, doctrine {decision.doctrine})")
    print(f"          obligations: {decision.obligations}")

    # two distinct human approvers sign the directive's hash with their own keys
    approver_a, approver_b = new_signer(), new_signer()
    rec.approve(directive.seq, "cto@acme", approver_a)
    status1 = rec.approval_status(directive.seq, threshold=2)
    rec.approve(directive.seq, "secops@acme", approver_b)
    status2 = rec.approval_status(directive.seq, threshold=2)
    print(f"   after 1 approval: satisfied={status1.satisfied} "
          f"({len(status1.approver_keys)}/{status1.threshold})")
    print(f"   after 2 approvals: satisfied={status2.satisfied} "
          f"({len(status2.approver_keys)}/{status2.threshold}) <- escalation cleared")

    # 2. Key rotation with a continuity proof: the OLD key signs the rotation
    #    entry naming the NEW key, so verification can prove the new key was
    #    authorized by the old -- no gap to hide a forged entry in.
    print("\nKey rotation with continuity proof:")
    old_alg = rec.signer.algorithm
    rec.rotate_key(new_signer(), actor="security-team")
    rec.submit("agent:ops", "db.migrate", {"db": "billing"})  # signed by the new key
    print(f"   rotated signing key (was {old_alg}); subsequent entries use the new key")

    # 3. The full record verifies, including the cross-key continuity.
    ok, broken = rec.verify(check_continuity=True)
    print(f"   ledger verify(continuity=True) -> intact={ok} first_broken={broken}")

    # 4. Hand a regulator a single self-contained file.
    bundle = rec.export_evidence()
    ok_offline, broken_off = verify_bundle(bundle)
    print(f"\nEvidence bundle ({bundle['format']}):")
    print(f"   entries={bundle['entry_count']} algorithm={bundle['algorithm']} "
          f"third_party_verifiable={bundle['third_party_verifiable']}")
    print(f"   head={bundle['head_hash'][:16]}...")
    print(f"   verify_bundle() offline -> intact={ok_offline} first_broken={broken_off}")
    print("\nApprovals, rotations and all -- one file an auditor checks without calling you.")


if __name__ == "__main__":
    main()
