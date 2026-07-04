"""Scenario 7 - Compliance/audit: one report over all five tools.

A compliance officer wants one document, not five CLIs. The capstone's
``build_report`` aggregates policy coverage (sentinel-policy), ledger integrity
(agentledger), git-authorization denials (repo-warden), and the code graph's
shape (codegraph-mcp) into a single report plus a maturity scorecard — and
renders it as Markdown, HTML, or SARIF (so gaps and denials surface as findings
in GitHub code scanning).

This builds a small real scenario and prints the scorecard, the finding count,
and confirms every render format is produced.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import rule, require, suite_status  # noqa: E402


def main() -> None:
    rule("UNIFIED COMPLIANCE REPORT  -  five tools, one document (MD / HTML / SARIF)")
    suite_status()
    if not require("agentledger"):
        return

    from accountable_suite import build_report, resolve
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
                {"id": "gate-deploy", "doctrine": "S3", "effect": "require_approval",
                 "tier": "high", "match": {"action": "deploy"}},
            ],
        })

    from agentledger import PolicyGate, Recorder
    gate = PolicyGate(default_allow=False)
    if policy is not None:
        gate.use(policy.as_gate_evaluator(defer_on_default=False))
    rec = Recorder(gate=gate)
    rec.submit("alice", "read.logs", {"lines": 10})
    rec.submit("mallory", "deploy", {"env": "prod"})  # gated -> a recorded refusal

    warden_audit = None
    if av.has("repo_warden"):
        import repo_warden as rw
        from repo_warden import Action, Store, Warden
        from accountable_suite import compat
        if compat.warden_supports_audit(rw):
            ws = Store()
            warden_audit = rw.AuditLog(ws)
            warden = compat.make_warden(Warden, ws, audit=warden_audit)
            tok, _ = ws.issue_token("agent:dev", {"branch:push"}, "acme/*")
            for br in ("feature/x", "main"):     # allow, then deny
                warden.authorize(tok, compat.make_action(
                    Action, op="push", repo="acme/api", branch=br))
        else:
            print("\n   (repo-warden lacks the audit surface; "
                  "warden section will show as not-evaluated)")

    graph_store = _sample_graph_store() if av.has("codegraph") else None

    report = build_report(title="Quarterly AI Governance Report", policy=policy,
                          recorder=rec, warden_audit=warden_audit,
                          graph_store=graph_store)

    sc = report.scorecard
    print(f"\n   maturity : {sc.level} ({sc.overall:.0f}/100)")
    for d in sc.dimensions:
        print(f"     {d.title:<26} {d.score:5.0f}  [{','.join(d.doctrine) or '-'}]")
    print(f"   findings : {len(report.findings)}")
    for f in report.findings[:4]:
        print(f"     - [{f.level}] {f.rule_id}: {f.message[:60]}")

    # every format renders; SARIF/JSON parse as valid documents
    import json
    md = report.to_markdown()
    html = report.to_html()
    sarif = json.loads(report.to_sarif())
    print(f"\n   rendered : markdown={len(md)}B, html={len(html)}B, "
          f"sarif results={len(sarif['runs'][0]['results'])}")
    print("\nOne artifact an auditor reads top to bottom — and a machine can gate on.")


if __name__ == "__main__":
    main()
