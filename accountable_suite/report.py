"""A unified compliance report aggregating all five suite tools.

Each tool answers a slice of "is this AI system under control?"; a compliance
officer wants one document, not five CLIs. ``ComplianceReport`` gathers:

  * the SENTINEL doctrine and the policy's coverage of it (sentinel-policy),
  * the ledger's integrity and the evidence-bundle head (agentledger),
  * the warden's authorization audit — including denials as findings
    (repo-warden),
  * the code graph's shape and no-train guarantee (codegraph-mcp),
  * a governance maturity scorecard (this package),

and renders to three formats a real compliance/security workflow already
speaks:

  * Markdown — human review, PR comments, wikis;
  * HTML     — a self-contained page (no external assets) for an audit binder;
  * SARIF 2.1.0 — denied authorizations and policy gaps surface as findings in
    GitHub code scanning / IDEs.

Everything is assembled from the *real* objects the caller passes in; a section
whose tool wasn't supplied is simply marked "not evaluated" rather than faked.
"""
from __future__ import annotations

import datetime as _dt
import html as _html
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import resolve
from .scorecard import Scorecard, build_scorecard

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    """One compliance finding (a policy gap or a denied authorization)."""
    rule_id: str
    level: str                    # error | warning | note
    message: str
    doctrine: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    title: str
    generated_at: str
    tools_present: Dict[str, bool]
    scorecard: Scorecard
    policy_section: Optional[dict] = None
    ledger_section: Optional[dict] = None
    warden_section: Optional[dict] = None
    graph_section: Optional[dict] = None
    findings: List[Finding] = field(default_factory=list)

    # ---- serialization ---------------------------------------------------
    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "tools_present": self.tools_present,
            "scorecard": self.scorecard.as_dict(),
            "policy": self.policy_section,
            "ledger": self.ledger_section,
            "warden": self.warden_section,
            "graph": self.graph_section,
            "findings": [
                {"rule_id": f.rule_id, "level": f.level, "message": f.message,
                 "doctrine": f.doctrine, "properties": f.properties}
                for f in self.findings
            ],
        }

    # ---- Markdown ---------------------------------------------------------
    def to_markdown(self) -> str:
        sc = self.scorecard
        L: List[str] = []
        L.append(f"# {self.title}")
        L.append("")
        L.append(f"_Generated {self.generated_at} — Accountable AI Engineering suite_")
        L.append("")
        L.append(f"**Governance maturity: {sc.level} ({sc.overall:.0f}/100)**")
        L.append("")
        # tools
        L.append("## Suite coverage")
        L.append("")
        L.append("| Tool | Present |")
        L.append("|------|:-------:|")
        for mod, present in self.tools_present.items():
            L.append(f"| {resolve.availability().label(mod)} | "
                     f"{'yes' if present else 'no'} |")
        L.append("")
        # scorecard
        L.append("## Maturity scorecard")
        L.append("")
        L.append("| Dimension | Doctrine | Score |")
        L.append("|-----------|----------|------:|")
        for d in sc.dimensions:
            L.append(f"| {d.title} | {', '.join(d.doctrine) or '—'} | {d.score:.0f} |")
        L.append("")
        # policy
        L.append("## Policy — doctrine coverage (sentinel-policy)")
        L.append("")
        if self.policy_section is None:
            L.append("_Not evaluated (no policy supplied)._")
        else:
            p = self.policy_section
            L.append(f"- Policy: **{p['name']}** (v{p['version']}), "
                     f"default `{p['default']}`, {p['rule_count']} rules")
            L.append(f"- Valid: **{'yes' if p['valid'] else 'NO'}**"
                     + ("" if p["valid"] else f" — problems: {p['problems']}"))
            L.append(f"- Doctrine covered: **{', '.join(p['covered']) or 'none'}** "
                     f"({p['coverage_pct']:.0f}%)")
            L.append(f"- Doctrine gaps: {', '.join(p['uncovered']) or 'none'}")
        L.append("")
        # ledger
        L.append("## Immutable record (agentledger)")
        L.append("")
        if self.ledger_section is None:
            L.append("_Not evaluated (no ledger supplied)._")
        else:
            l = self.ledger_section
            L.append(f"- Entries: **{l['entry_count']}**, signing `{l['algorithm']}`")
            L.append(f"- Ledger verifies: **{'yes' if l['verifies'] else 'NO'}**")
            L.append(f"- Evidence head hash: `{l['head_hash'][:16]}…`")
            L.append(f"- Offline-verifiable bundle: "
                     f"**{'yes' if l['offline_verifiable'] else 'no'}**")
        L.append("")
        # warden
        L.append("## Least authority — git access (repo-warden)")
        L.append("")
        if self.warden_section is None:
            L.append("_Not evaluated (no warden audit supplied)._")
        else:
            w = self.warden_section
            L.append(f"- Authorization events: **{w['events']}** "
                     f"({w['denied']} denied)")
            L.append(f"- Audit chain intact: **{'yes' if w['audit_ok'] else 'NO'}**")
        L.append("")
        # graph
        L.append("## Grounded understanding (codegraph-mcp)")
        L.append("")
        if self.graph_section is None:
            L.append("_Not evaluated (no code graph supplied)._")
        else:
            g = self.graph_section
            L.append(f"- Files: {g['files']}, symbols: {g['symbols']}, "
                     f"cross-language edges: {g['cross_language_edges']}")
            L.append(f"- Languages: {', '.join(sorted(g['languages'])) or 'none'}")
            L.append("- No-train guarantee: the graph is built only to answer "
                     "queries; nothing is used to train a model.")
        L.append("")
        # findings
        L.append("## Findings")
        L.append("")
        if not self.findings:
            L.append("_No findings — no policy gaps and no denied authorizations "
                     "in the evaluated evidence._")
        else:
            L.append("| Level | Rule | Doctrine | Message |")
            L.append("|-------|------|----------|---------|")
            for f in self.findings:
                L.append(f"| {f.level} | `{f.rule_id}` | {f.doctrine or '—'} | "
                         f"{f.message} |")
        L.append("")
        return "\n".join(L)

    # ---- HTML -------------------------------------------------------------
    def to_html(self) -> str:
        md_as_dict = self.as_dict()
        sc = self.scorecard
        e = _html.escape

        def rows(pairs):
            return "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>"
                           for k, v in pairs)

        dim_rows = "".join(
            f"<tr><td>{e(d.title)}</td><td>{e(', '.join(d.doctrine) or '—')}</td>"
            f"<td style='text-align:right'>{d.score:.0f}</td></tr>"
            for d in sc.dimensions)
        tool_rows = "".join(
            f"<tr><td>{e(resolve.availability().label(m))}</td>"
            f"<td>{'yes' if p else 'no'}</td></tr>"
            for m, p in self.tools_present.items())
        find_rows = "".join(
            f"<tr><td>{e(f.level)}</td><td><code>{e(f.rule_id)}</code></td>"
            f"<td>{e(f.doctrine or '—')}</td><td>{e(f.message)}</td></tr>"
            for f in self.findings) or (
            "<tr><td colspan='4'><em>No findings.</em></td></tr>")

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(self.title)}</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
 h1{{margin-bottom:.2rem}} .meta{{color:#666;font-size:.9rem}}
 .badge{{display:inline-block;padding:.3rem .7rem;border-radius:.4rem;background:#0d3b66;color:#fff;font-weight:600}}
 table{{border-collapse:collapse;width:100%;margin:.6rem 0}}
 th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}}
 th{{background:#f4f6f8}} code{{background:#f0f0f0;padding:.1rem .3rem;border-radius:.2rem}}
 section{{margin:1.4rem 0}}
</style></head><body>
<h1>{e(self.title)}</h1>
<p class="meta">Generated {e(self.generated_at)} — Accountable AI Engineering suite</p>
<p><span class="badge">Governance maturity: {e(sc.level)} — {sc.overall:.0f}/100</span></p>
<section><h2>Suite coverage</h2>
<table><tr><th>Tool</th><th>Present</th></tr>{tool_rows}</table></section>
<section><h2>Maturity scorecard</h2>
<table><tr><th>Dimension</th><th>Doctrine</th><th>Score</th></tr>{dim_rows}</table></section>
<section><h2>Policy — doctrine coverage</h2>{self._html_policy(e)}</section>
<section><h2>Immutable record</h2>{self._html_ledger(e)}</section>
<section><h2>Least authority — git access</h2>{self._html_warden(e)}</section>
<section><h2>Grounded understanding</h2>{self._html_graph(e)}</section>
<section><h2>Findings</h2>
<table><tr><th>Level</th><th>Rule</th><th>Doctrine</th><th>Message</th></tr>{find_rows}</table></section>
</body></html>"""

    def _html_policy(self, e) -> str:
        p = self.policy_section
        if p is None:
            return "<p><em>Not evaluated.</em></p>"
        return (f"<p>Policy <strong>{e(p['name'])}</strong> (v{p['version']}), "
                f"default <code>{e(p['default'])}</code>, {p['rule_count']} rules. "
                f"Valid: <strong>{'yes' if p['valid'] else 'NO'}</strong>. "
                f"Doctrine covered: <strong>{e(', '.join(p['covered']) or 'none')}</strong> "
                f"({p['coverage_pct']:.0f}%); gaps: "
                f"{e(', '.join(p['uncovered']) or 'none')}.</p>")

    def _html_ledger(self, e) -> str:
        l = self.ledger_section
        if l is None:
            return "<p><em>Not evaluated.</em></p>"
        return (f"<p>{l['entry_count']} entries, signing <code>{e(l['algorithm'])}</code>. "
                f"Verifies: <strong>{'yes' if l['verifies'] else 'NO'}</strong>. "
                f"Evidence head <code>{e(l['head_hash'][:16])}…</code>, "
                f"offline-verifiable: <strong>"
                f"{'yes' if l['offline_verifiable'] else 'no'}</strong>.</p>")

    def _html_warden(self, e) -> str:
        w = self.warden_section
        if w is None:
            return "<p><em>Not evaluated.</em></p>"
        return (f"<p>{w['events']} authorization events ({w['denied']} denied). "
                f"Audit chain intact: <strong>"
                f"{'yes' if w['audit_ok'] else 'NO'}</strong>.</p>")

    def _html_graph(self, e) -> str:
        g = self.graph_section
        if g is None:
            return "<p><em>Not evaluated.</em></p>"
        return (f"<p>{g['files']} files, {g['symbols']} symbols, "
                f"{g['cross_language_edges']} cross-language edges. "
                f"Languages: {e(', '.join(sorted(g['languages'])) or 'none')}. "
                f"No-train: the graph is built only to answer queries.</p>")

    # ---- SARIF ------------------------------------------------------------
    def to_sarif(self) -> str:
        rule_ids: List[str] = []
        seen = set()
        for f in self.findings:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                rule_ids.append(f.rule_id)
        rules = [{
            "id": rid,
            "name": rid.split("/", 1)[-1],
            "shortDescription": {"text": f"accountable-ai-suite finding: {rid}"},
        } for rid in rule_ids]

        results = []
        for f in self.findings:
            props = dict(f.properties)
            if f.doctrine:
                props["doctrine"] = f.doctrine
            results.append({
                "ruleId": f.rule_id,
                "level": f.level,
                "message": {"text": f.message},
                "properties": props,
            })
        doc = {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA,
            "runs": [{
                "tool": {"driver": {
                    "name": "accountable-ai-suite",
                    "informationUri": "https://github.com/cognis-digital/accountable-ai-suite",
                    "rules": rules,
                }},
                "results": results,
            }],
        }
        return json.dumps(doc, indent=2)

    def render(self, fmt: str = "markdown") -> str:
        fmt = fmt.lower()
        if fmt in ("md", "markdown"):
            return self.to_markdown()
        if fmt == "html":
            return self.to_html()
        if fmt == "sarif":
            return self.to_sarif()
        if fmt == "json":
            return json.dumps(self.as_dict(), indent=2)
        raise ValueError(f"unknown format '{fmt}'; choose markdown|html|sarif|json")


def build_report(*, title: str = "AI Governance Compliance Report",
                 policy: Any = None, recorder: Any = None,
                 warden_audit: Any = None, graph_store: Any = None
                 ) -> ComplianceReport:
    """Assemble a unified report from the real objects you have on hand.

    All inputs optional. Pass a ``sentinel_policy.Policy``, an agentledger
    ``Recorder`` (or anything with ``verify``/``export_evidence``/``entries``),
    a ``repo_warden.AuditLog``, and/or a ``codegraph.graph.Store``. Whatever is
    supplied is evaluated with live checks; the rest is marked not-evaluated.
    """
    av = resolve.availability()
    findings: List[Finding] = []

    # ---- policy ----------------------------------------------------------
    policy_section = None
    if policy is not None:
        cov = policy.doctrine_coverage()
        problems = policy.validate()
        try:
            from sentinel_policy import build_report as _sp_report
            rpt = _sp_report(policy)
            cov_pct = rpt.coverage_pct
            valid = rpt.valid
        except Exception:
            total = 7
            cov_pct = 100.0 * len(cov["covered"]) / total
            valid = not problems
        policy_section = {
            "name": policy.name, "version": policy.version,
            "default": policy.default.value if hasattr(policy.default, "value")
            else str(policy.default),
            "rule_count": len(policy.rules), "valid": valid,
            "problems": problems, "covered": cov["covered"],
            "uncovered": cov["uncovered"], "coverage_pct": cov_pct,
        }
        # doctrine gaps become findings so they surface in SARIF/PR review
        for gap in cov["uncovered"]:
            findings.append(Finding(
                rule_id=f"suite/doctrine-gap/{gap}", level="warning",
                message=f"SENTINEL rule {gap} is not cited by any policy rule "
                        "(is this gap intentional?)",
                doctrine=gap, properties={"kind": "doctrine_gap"}))
        for prob in problems:
            findings.append(Finding(
                rule_id="suite/policy-invalid", level="error",
                message=prob, properties={"kind": "policy_problem"}))

    # ---- ledger ----------------------------------------------------------
    ledger_section = None
    ledger_verifies = None
    refusals_recorded = None
    if recorder is not None:
        ok, _ = recorder.verify()
        bundle = recorder.export_evidence()
        offline = False
        if av.has("agentledger"):
            try:
                from agentledger.evidence import verify_bundle
                offline, _ = verify_bundle(bundle)
            except Exception:
                offline = False
        ledger_verifies = bool(ok)
        # a recorded refusal = a directive entry whose decision denied it
        refusals_recorded = any(
            e.kind == "directive" and e.decision
            and e.decision.get("allowed") is False
            for e in recorder.entries())
        ledger_section = {
            "entry_count": bundle.get("entry_count", 0),
            "algorithm": bundle.get("algorithm", "?"),
            "head_hash": bundle.get("head_hash", ""),
            "verifies": ledger_verifies, "offline_verifiable": offline,
        }
        if not ok:
            findings.append(Finding(
                rule_id="suite/ledger-tampered", level="error",
                message="agentledger ledger failed verification (chain or "
                        "signature broken)", doctrine="S4",
                properties={"kind": "ledger_integrity"}))

    # ---- warden ----------------------------------------------------------
    warden_section = None
    warden_audit_ok = None
    if warden_audit is not None:
        vr = warden_audit.verify()
        events = warden_audit.events()
        denied = [e for e in events if not e.allowed]
        warden_audit_ok = bool(vr.ok)
        warden_section = {
            "events": len(events), "denied": len(denied),
            "audit_ok": warden_audit_ok,
        }
        if not vr.ok:
            findings.append(Finding(
                rule_id="suite/warden-audit-tampered", level="error",
                message=f"repo-warden audit chain broken at seq {vr.broken_seq}",
                doctrine="S2", properties={"kind": "warden_integrity"}))
        for ev in denied:
            findings.append(Finding(
                rule_id=f"warden/{ev.rule}", level="warning",
                message=f"DENIED: {ev.op} {ev.repo}@{ev.branch or '-'}"
                        + (f" — {ev.reason}" if ev.reason else ""),
                doctrine="S2",
                properties={"op": ev.op, "repo": ev.repo, "branch": ev.branch,
                            "actor": ev.actor, "kind": "denied_authorization"}))

    # ---- graph -----------------------------------------------------------
    graph_section = None
    graph_available = av.has("codegraph")
    if graph_store is not None:
        st = graph_store.stats()
        graph_section = {
            "files": st["files"], "symbols": st["symbols"],
            "cross_language_edges": st["cross_language_edges"],
            "languages": list(st["languages"].keys()),
        }
        graph_available = True

    scorecard = build_scorecard(
        policy=policy, ledger_verifies=ledger_verifies,
        refusals_recorded=refusals_recorded, warden_audit_ok=warden_audit_ok,
        graph_available=graph_available if graph_store is not None else None)

    return ComplianceReport(
        title=title, generated_at=_now_iso(), tools_present=av.as_dict(),
        scorecard=scorecard, policy_section=policy_section,
        ledger_section=ledger_section, warden_section=warden_section,
        graph_section=graph_section, findings=findings)
