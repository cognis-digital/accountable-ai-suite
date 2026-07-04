"""Scenario 8 - Auditor/IR: one integrity check across every artifact.

An auditor handed a stack of evidence shouldn't need three verify subcommands.
``verify_all`` re-walks every integrity artifact the suite produces — the
agentledger evidence bundle (hash chain + Ed25519 signatures + key continuity),
the repo-warden audit chain, and the codegraph audit chain — and returns one
verdict. The evidence-bundle path is pure Python: it validates a bundle handed
over offline, with no access to the systems that produced it.

This produces real artifacts, verifies them (all OK), then tampers with one and
shows the check catch it and name the broken record.
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import rule, require, suite_status  # noqa: E402


def main() -> None:
    rule("SUITE VERIFY  -  one integrity verdict across every artifact")
    suite_status()
    if not require("agentledger"):
        return

    from accountable_suite import verify_all, resolve
    from accountable_suite.verify import verify_evidence_bundle
    from accountable_suite.orchestrator import _sample_graph_store

    av = resolve.availability()

    from agentledger import Recorder
    rec = Recorder()
    rec.submit("alice", "read.logs", {"lines": 10})
    rec.submit("agent", "deploy", {"env": "staging"})
    bundle = rec.export_evidence()

    warden_audit = None
    if av.has("repo_warden"):
        from repo_warden import Action, AuditLog, Store, Warden
        ws = Store()
        warden_audit = AuditLog(ws)
        warden = Warden(ws, audit=warden_audit)
        tok, _ = ws.issue_token("agent:dev", {"branch:push"}, "acme/*")
        warden.authorize(tok, Action("push", "acme/api", "feature/x"))

    graph_store = _sample_graph_store() if av.has("codegraph") else None

    print("\n   verifying every live artifact:")
    report = verify_all(recorder=rec, warden_audit=warden_audit,
                        graph_store=graph_store)
    print("   " + report.render().replace("\n", "\n   "))

    # now hand an auditor just the bundle — no DB, no network — and verify it
    ok_bundle = verify_evidence_bundle(bundle)
    print(f"\n   offline bundle check (no DB/network): ok={ok_bundle.ok} "
          f"({ok_bundle.checked} entries, {ok_bundle.detail})")

    # tamper: flip a recorded action in the bundle and re-verify
    tampered = copy.deepcopy(bundle)
    if tampered["entries"]:
        tampered["entries"][0]["action"] = "read.everything"
    bad = verify_evidence_bundle(tampered)
    print(f"   tampered bundle detected: ok={bad.ok}, broke at seq {bad.broken_at}")
    print("\nOne verdict, and tampering is not just detected — it's located.")


if __name__ == "__main__":
    main()
