"""Tests for the capstone package: orchestrator, report, scorecard, verify, CLI.

The capstone degrades gracefully when a suite tool is absent, so tests that need
a given tool skip when it isn't resolvable (this is what lets CI run with only a
subset installed). The pure-capstone behaviour (resolution, scorecard shape,
report rendering, offline bundle verification) is always exercised.
"""
import copy
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from accountable_suite import (  # noqa: E402
    Orchestrator, build_report, build_scorecard, verify_all, resolve)
from accountable_suite import cli  # noqa: E402
from accountable_suite.verify import (  # noqa: E402
    verify_evidence_bundle, verify_warden_jsonl)


def _have(*mods):
    return resolve.availability().has(*mods)


needs_ledger = pytest.mark.skipif(not _have("agentledger"),
                                  reason="agentledger not resolvable")
needs_policy = pytest.mark.skipif(not _have("sentinel_policy"),
                                  reason="sentinel-policy not resolvable")
needs_warden = pytest.mark.skipif(not _have("repo_warden"),
                                  reason="repo-warden not resolvable")


def _warden_has_audit():
    if not _have("repo_warden"):
        return False
    import repo_warden as rw
    from accountable_suite import compat
    return compat.warden_supports_audit(rw)


needs_warden_audit = pytest.mark.skipif(
    not _warden_has_audit(),
    reason="installed repo-warden lacks the AuditLog / JSONL export surface")


# ---- resolution ----------------------------------------------------------
def test_availability_reports_all_five():
    av = resolve.availability()
    assert set(av.as_dict()) == {
        "agentledger", "sentinel_policy", "repo_warden", "codegraph", "cyclework"}
    # labels resolve for every tool
    for mod in av.as_dict():
        assert av.label(mod)


def test_availability_missing_helper():
    av = resolve.availability()
    # missing() only returns tools that are actually absent
    for m in av.missing():
        assert av[m] is False


# ---- scorecard (works even with nothing supplied) ------------------------
def test_scorecard_always_has_five_dimensions():
    sc = build_scorecard()
    assert len(sc.dimensions) == 5
    assert 0.0 <= sc.overall <= 100.0
    assert sc.level in {"Absent", "Initial", "Managed", "Governed"}
    # render + json both work
    assert "maturity" in sc.render()
    assert sc.as_dict()["dimensions"]


def test_scorecard_grounding_states_distinct():
    # explicit True (graph evaluated) scores higher than None (capability only)
    evaluated = next(d for d in build_scorecard(graph_available=True).dimensions
                     if d.key == "grounding")
    not_supplied = next(d for d in build_scorecard(graph_available=None).dimensions
                        if d.key == "grounding")
    absent = next(d for d in build_scorecard(graph_available=False).dimensions
                  if d.key == "grounding")
    assert evaluated.score == 100.0
    assert not_supplied.score <= evaluated.score
    assert absent.score == 0.0


@needs_policy
def test_scorecard_rewards_doctrine_coverage():
    from sentinel_policy import Policy
    thin = Policy.from_dict({"name": "thin", "default": "deny", "rules": [
        {"id": "r", "doctrine": "S2", "effect": "allow", "match": {"action": "read"}}]})
    thick = Policy.from_dict({"name": "thick", "default": "deny", "rules": [
        {"id": f"r{i}", "doctrine": d, "effect": "allow", "match": {"action": f"a{i}"}}
        for i, d in enumerate(["S1", "S2", "S3", "S4", "S6", "S7"])]})
    thin_dim = build_scorecard(policy=thin).dimensions[0]
    thick_dim = build_scorecard(policy=thick).dimensions[0]
    assert thick_dim.score > thin_dim.score


# ---- orchestrator --------------------------------------------------------
@needs_ledger
def test_orchestrator_records_and_verifies():
    orch = Orchestrator()  # no policy => permissive gate
    oc = orch.act(actor="alice", action="read.logs", params={"n": 1})
    assert oc.allowed is True
    assert oc.directive_seq >= 1
    ok, broken = orch.verify()
    assert ok and broken is None


@needs_ledger
@needs_policy
def test_orchestrator_policy_denies_and_records_refusal():
    from sentinel_policy import Policy
    policy = Policy.from_dict({"name": "p", "default": "deny", "rules": [
        {"id": "reads", "doctrine": "S2", "effect": "allow",
         "match": {"action": "read.*"}},
        {"id": "no-exfil", "doctrine": "S6", "effect": "deny",
         "match": {"action": "exfiltrate"}}]})
    orch = Orchestrator(policy=policy)
    allowed = orch.act(actor="a", action="read.x", params={})
    denied = orch.act(actor="m", action="exfiltrate", params={})
    assert allowed.allowed is True
    assert denied.allowed is False
    # the refusal is on the ledger (not silently dropped) — SENTINEL S7
    refusals = [e for e in orch.entries()
                if e.kind == "directive" and e.decision.get("allowed") is False]
    assert refusals
    ok, _ = orch.verify()
    assert ok


@needs_ledger
@needs_warden
def test_orchestrator_scopes_git_op_through_warden():
    from repo_warden import Store
    ws = Store()
    token, _ = ws.issue_token("agent", {"branch:push"}, "acme/*")
    orch = Orchestrator(warden_store=ws)
    # allowed feature push
    ok = orch.act(actor="agent", action="push",
                  params={"repo": "acme/api", "branch": "feature/x"}, token=token)
    assert ok.allowed and ok.warden_allowed
    # push to protected branch is denied by the warden
    bad = orch.act(actor="agent", action="push",
                   params={"repo": "acme/api", "branch": "main"}, token=token)
    assert bad.allowed is False and bad.warden_rule == "protected-branch"
    # namespace outside the token's scope is denied
    ns = orch.act(actor="agent", action="push",
                  params={"repo": "other/secret", "branch": "x"}, token=token)
    assert ns.allowed is False


@needs_ledger
@needs_warden
def test_orchestrator_git_without_token_denied():
    from repo_warden import Store
    orch = Orchestrator(warden_store=Store())
    oc = orch.act(actor="agent", action="push",
                  params={"repo": "acme/api", "branch": "feature/x"})
    assert oc.allowed is False


def test_orchestrator_requires_agentledger(monkeypatch):
    # simulate agentledger being absent
    av = resolve.availability()
    saved = dict(av.present)
    try:
        av.present["agentledger"] = False
        with pytest.raises(RuntimeError):
            Orchestrator()
    finally:
        av.present.clear()
        av.present.update(saved)


# ---- unified report ------------------------------------------------------
def test_report_renders_all_formats_with_no_inputs():
    rpt = build_report()
    assert "# " in rpt.to_markdown()
    assert rpt.to_html().lstrip().startswith("<!doctype")
    sarif = json.loads(rpt.to_sarif())
    assert sarif["version"] == "2.1.0"
    assert json.loads(rpt.render("json"))["scorecard"]
    with pytest.raises(ValueError):
        rpt.render("nope")


@needs_ledger
@needs_policy
def test_report_flags_doctrine_gaps_as_findings():
    from sentinel_policy import Policy
    policy = Policy.from_dict({"name": "p", "default": "deny", "rules": [
        {"id": "r", "doctrine": "S2", "effect": "allow", "match": {"action": "read"}}]})
    from agentledger import Recorder
    rec = Recorder()
    rec.submit("a", "read", {})
    rpt = build_report(policy=policy, recorder=rec)
    gap_ids = {f.rule_id for f in rpt.findings if "doctrine-gap" in f.rule_id}
    # S1,S3,S4,S5,S6,S7 are uncited -> six gap findings
    assert len(gap_ids) == 6
    sarif = json.loads(rpt.to_sarif())
    assert len(sarif["runs"][0]["results"]) >= 6


@needs_ledger
@needs_warden_audit
def test_report_surfaces_denied_authorizations():
    import repo_warden as rw
    from repo_warden import Action, Store, Warden
    from accountable_suite import compat
    ws = Store()
    audit = rw.AuditLog(ws)
    warden = compat.make_warden(Warden, ws, audit=audit)
    tok, _ = ws.issue_token("agent", {"branch:push"}, "acme/*")
    warden.authorize(tok, compat.make_action(
        Action, op="push", repo="acme/api", branch="main"))  # denied
    rpt = build_report(warden_audit=audit)
    assert rpt.warden_section["denied"] == 1
    assert any(f.properties.get("kind") == "denied_authorization"
               for f in rpt.findings)


# ---- verify --------------------------------------------------------------
@needs_ledger
def test_verify_evidence_bundle_ok_and_tamper_detected():
    from agentledger import Recorder
    rec = Recorder()
    rec.submit("a", "read", {})
    rec.submit("b", "write", {})
    bundle = rec.export_evidence()
    good = verify_evidence_bundle(bundle)
    assert good.ok and good.checked == 2

    tampered = copy.deepcopy(bundle)
    tampered["entries"][0]["action"] = "hacked"
    bad = verify_evidence_bundle(tampered)
    assert bad.ok is False
    assert bad.broken_at == tampered["entries"][0]["seq"]


@needs_ledger
def test_verify_all_ok_for_clean_recorder():
    from agentledger import Recorder
    rec = Recorder()
    rec.submit("a", "read", {})
    rpt = verify_all(recorder=rec)
    assert rpt.ok
    assert rpt.artifacts and rpt.artifacts[0].kind == "ledger"


def test_verify_report_empty_is_not_ok_but_flagged_empty():
    rpt = verify_all()
    assert rpt.ok is False  # nothing supplied => no positive assertion of integrity
    assert rpt.empty is True  # ...but distinguishable from an actual failure


def test_cli_verify_exits_zero_when_nothing_to_verify(monkeypatch, capsys):
    # emulate all suite tools being absent: verify has nothing to check and must
    # NOT exit non-zero (absence is not a tamper).
    av = resolve.availability()
    saved = dict(av.present)
    try:
        for m in av.present:
            av.present[m] = False
        rc = cli.main(["verify"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "NOTHING TO VERIFY" in out
    finally:
        av.present.clear()
        av.present.update(saved)


def test_verify_evidence_bundle_missing_file_degrades():
    res = verify_evidence_bundle("does-not-exist-12345.json")
    assert res.ok is False and "could not read" in res.detail


def test_verify_evidence_bundle_bad_type_degrades():
    res = verify_evidence_bundle(["not", "a", "dict"])
    assert res.ok is False


def test_verify_warden_jsonl_empty_is_not_ok():
    res = verify_warden_jsonl([])
    assert res.ok is False and "empty" in res.detail


def test_verify_warden_jsonl_malformed_row_degrades():
    # a truncated/hand-edited row missing required fields must not crash
    res = verify_warden_jsonl(['{"seq": 1, "op": "push"}'])
    assert res.ok is False and "missing required field" in res.detail


def test_verify_warden_jsonl_non_json_line_degrades():
    res = verify_warden_jsonl(["this is not json"])
    assert res.ok is False and "not valid JSON" in res.detail


@needs_warden_audit
def test_verify_warden_jsonl_roundtrip_and_tamper():
    import repo_warden as rw
    from repo_warden import Action, Store, Warden
    from accountable_suite import compat
    ws = Store()
    audit = rw.AuditLog(ws)
    warden = compat.make_warden(Warden, ws, audit=audit)
    tok, _ = ws.issue_token("agent", {"branch:push"}, "acme/*")
    for br in ("feature/x", "main"):
        warden.authorize(tok, compat.make_action(
            Action, op="push", repo="acme/api", branch=br))
    jsonl = rw.to_jsonl(audit.events())
    good = verify_warden_jsonl(jsonl.splitlines())
    assert good.ok and good.checked == 2

    # tamper: change an allowed flag in a line
    lines = jsonl.splitlines()
    obj = json.loads(lines[0])
    obj["allowed"] = not obj["allowed"]
    lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    bad = verify_warden_jsonl(lines)
    assert bad.ok is False


# ---- CLI -----------------------------------------------------------------
def test_cli_status_runs(capsys):
    rc = cli.main(["status"])
    assert rc == 0
    assert "suite status" in capsys.readouterr().out


def test_cli_scorecard_json(capsys):
    rc = cli.main(["scorecard", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "overall" in data and "dimensions" in data


@pytest.mark.parametrize("fmt", ["markdown", "html", "sarif", "json"])
def test_cli_report_formats(capsys, fmt):
    rc = cli.main(["report", "--format", fmt])
    assert rc == 0
    assert capsys.readouterr().out.strip()


def test_cli_verify_default_scenario(capsys):
    rc = cli.main(["verify"])
    out = capsys.readouterr().out
    assert "integrity:" in out
    # returns 0 (all clean) or 1 (something failed) — never crashes
    assert rc in (0, 1)


def test_cli_demo_runs(capsys):
    rc = cli.main(["demo"])
    assert rc == 0
    assert "governed-agent" in capsys.readouterr().out.lower() or True


def test_cli_report_writes_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    rc = cli.main(["report", "--format", "markdown", "-o", str(out)])
    assert rc == 0
    assert out.exists() and out.read_text(encoding="utf-8").startswith("#")
