"""`suite` — a richer command-line over the capstone capabilities.

    suite status                     which of the five tools are resolvable
    suite scorecard [--json]         governance maturity scorecard
    suite report  [--format md|html|sarif|json] [-o FILE]
                                     unified compliance report
    suite verify  --bundle FILE      verify an evidence bundle offline
                  [--warden-jsonl FILE]
    suite demo    [--format ...]     run the reference scenario end to end and
                                     print/scorecard/report/verify it

With no evidence supplied, `scorecard`, `report`, and `demo` build a small,
real reference scenario (a governed agent run) so the commands always produce
something meaningful — every tool that's installed is actually exercised.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import build_report, build_scorecard, verify_all
from . import resolve
from .verify import verify_evidence_bundle, verify_warden_jsonl, VerifyReport


def _reference_scenario():
    """Build a real, small governed-agent scenario from whatever is installed.

    Returns (policy, recorder, warden_audit, graph_store) — any of which may be
    None if the relevant tool isn't resolvable. This is the same scenario the
    reference example and the demo use, kept here so the CLI can always show a
    live, non-empty result.
    """
    av = resolve.availability()
    policy = recorder = warden_audit = graph_store = None

    if av.has("sentinel_policy"):
        from sentinel_policy import Policy
        policy = Policy.from_dict({
            "name": "prod-controls", "default": "deny",
            "rules": [
                {"id": "reads-ok", "doctrine": "S2", "effect": "allow",
                 "match": {"action": "read.*"}},
                {"id": "audit-writes", "doctrine": "S4", "effect": "allow",
                 "match": {"action": "push"}},
                {"id": "gate-prod-deploy", "doctrine": "S3",
                 "effect": "require_approval", "tier": "high",
                 "match": {"action": "deploy", "params.env": {"eq": "prod"}}},
                {"id": "deny-secrets-xfer", "doctrine": "S6", "effect": "deny",
                 "match": {"action": "exfiltrate"}},
            ],
        })

    if av.has("agentledger"):
        from agentledger import PolicyGate, Recorder
        gate = PolicyGate(default_allow=False)
        if policy is not None:
            gate.use(policy.as_gate_evaluator(defer_on_default=False))
        recorder = Recorder(gate=gate)
        recorder.submit("alice", "read.logs", {"lines": 100})
        recorder.submit("mallory", "deploy", {"env": "prod"})       # gated
        recorder.submit("mallory", "exfiltrate", {"to": "external"})  # denied (S6)

    if av.has("repo_warden"):
        from repo_warden import Action, AuditLog, Store, Warden
        ws = Store()
        warden_audit = AuditLog(ws)
        warden = Warden(ws, audit=warden_audit)
        token, _ = ws.issue_token("agent:dev", {"branch:push"}, "acme/*")
        warden.authorize(token, Action("push", "acme/api", "feature/x"))  # allow
        warden.authorize(token, Action("push", "acme/api", "main"))       # deny
        warden.authorize(token, Action("push", "other/secret", "x"))      # deny

    if av.has("codegraph"):
        from .orchestrator import _sample_graph_store
        graph_store = _sample_graph_store()

    return policy, recorder, warden_audit, graph_store


def _cmd_status(args) -> int:
    av = resolve.availability()
    print("Accountable AI Engineering — suite status\n")
    for mod, present in av.as_dict().items():
        print(f"  [{'ok ' if present else 'MISSING'}] {av.label(mod)}")
    return 0


def _cmd_scorecard(args) -> int:
    policy, recorder, warden_audit, graph_store = _reference_scenario()
    ledger_ok = recorder.verify()[0] if recorder is not None else None
    refusals = None
    if recorder is not None:
        refusals = any(e.kind == "directive" and e.decision
                       and e.decision.get("allowed") is False
                       for e in recorder.entries())
    warden_ok = warden_audit.verify().ok if warden_audit is not None else None
    sc = build_scorecard(policy=policy, ledger_verifies=ledger_ok,
                         refusals_recorded=refusals, warden_audit_ok=warden_ok,
                         graph_available=graph_store is not None)
    if args.json:
        print(json.dumps(sc.as_dict(), indent=2))
    else:
        print(sc.render())
    return 0


def _cmd_report(args) -> int:
    policy, recorder, warden_audit, graph_store = _reference_scenario()
    rpt = build_report(policy=policy, recorder=recorder,
                       warden_audit=warden_audit, graph_store=graph_store)
    out = rpt.render(args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {args.format} report -> {args.output}")
    else:
        print(out)
    return 0


def _cmd_verify(args) -> int:
    if not any([args.bundle, args.warden_jsonl]):
        # nothing pointed at: verify the reference scenario's live artifacts
        _, recorder, warden_audit, graph_store = _reference_scenario()
        rpt = verify_all(recorder=recorder, warden_audit=warden_audit,
                         graph_store=graph_store)
    else:
        rpt = VerifyReport()
        if args.bundle:
            rpt.artifacts.append(verify_evidence_bundle(args.bundle))
        if args.warden_jsonl:
            rpt.artifacts.append(verify_warden_jsonl(args.warden_jsonl))
    print(rpt.render())
    # exit non-zero only when an artifact actually FAILED; "nothing to verify"
    # (no tools/artifacts present) is not an integrity failure.
    return 1 if (not rpt.ok and not rpt.empty) else 0


def _cmd_demo(args) -> int:
    from .orchestrator import Orchestrator, _sample_graph_store
    av = resolve.availability()
    if not av.has("agentledger"):
        print("demo needs at least agentledger; none resolvable — skipping.")
        return 0

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
                {"id": "deny-secrets", "doctrine": "S6", "effect": "deny",
                 "match": {"action": "exfiltrate"}},
            ],
        })
    warden_store = None
    token = None
    if av.has("repo_warden"):
        from repo_warden import AuditLog, Store
        warden_store = Store()
        warden_audit = AuditLog(warden_store)
        token, _ = warden_store.issue_token("agent:dev", {"branch:push"}, "acme/*")
    else:
        warden_audit = None

    graph_store = _sample_graph_store() if av.has("codegraph") else None
    orch = Orchestrator(policy=policy, warden_store=warden_store,
                        graph_store=graph_store)
    if warden_store is not None:
        orch.warden.audit = warden_audit  # capture events for the report

    print("Reference governed-agent run (single suite.act() calls):\n")
    for actor, action, params in [
        ("alice", "read.logs", {"lines": 50}),
        ("agent:dev", "push", {"repo": "acme/api", "branch": "feature/x"}),
        ("agent:dev", "push", {"repo": "acme/api", "branch": "main"}),
        ("mallory", "exfiltrate", {"to": "external"}),
    ]:
        oc = orch.act(actor=actor, action=action, params=params, token=token)
        gv = f" warden={oc.warden_rule}" if oc.warden_rule is not None else ""
        print(f"  {actor:<10} {action:<12} -> allowed={oc.allowed!s:<5} "
              f"policy={oc.policy_rule}{gv}")

    ok, broken = orch.verify()
    bundle = orch.export_evidence()
    print(f"\nledger verifies={ok} (broken={broken}), "
          f"{bundle['entry_count']} entries, head {bundle['head_hash'][:12]}…")

    rpt = build_report(policy=policy, recorder=orch.recorder,
                       warden_audit=warden_audit, graph_store=graph_store)
    print(f"\nmaturity: {rpt.scorecard.level} "
          f"({rpt.scorecard.overall:.0f}/100), findings: {len(rpt.findings)}")
    if args.format:
        print("\n" + rpt.render(args.format))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="suite", description="Accountable AI Engineering — capstone CLI")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("status", help="show which suite tools are resolvable")

    sc = sub.add_parser("scorecard", help="governance maturity scorecard")
    sc.add_argument("--json", action="store_true", help="emit JSON")

    rp = sub.add_parser("report", help="unified compliance report")
    rp.add_argument("--format", default="markdown",
                    choices=["markdown", "md", "html", "sarif", "json"])
    rp.add_argument("-o", "--output", help="write to a file instead of stdout")

    vf = sub.add_parser("verify", help="verify integrity artifacts")
    vf.add_argument("--bundle", help="agentledger evidence bundle (JSON file)")
    vf.add_argument("--warden-jsonl", help="repo-warden JSONL audit export")

    dm = sub.add_parser("demo", help="run the reference governed-agent scenario")
    dm.add_argument("--format", help="also render a report in this format",
                    choices=["markdown", "md", "html", "sarif", "json"])
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cmd = args.cmd or "status"
    handler = {
        "status": _cmd_status, "scorecard": _cmd_scorecard,
        "report": _cmd_report, "verify": _cmd_verify, "demo": _cmd_demo,
    }[cmd]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
