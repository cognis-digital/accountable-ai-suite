"""Cross-tool integrity verification: the `suite verify` command.

A regulator or an on-call engineer doesn't want to run three different
`verify` subcommands and reconcile them by eye. This checks every integrity
artifact the suite can produce, in one pass, and returns a single verdict plus
a per-artifact breakdown:

  * an agentledger evidence bundle — hash chain + (Ed25519) signatures + key
    continuity, verified with no access to the original database;
  * a repo-warden audit export (JSONL) — the BLAKE2b hash chain re-walked;
  * a codegraph audit log — likewise (if a graph DB is supplied).

Each artifact is optional; ``verify_all`` verifies whatever you point it at and
reports ``ok`` only if *every* supplied artifact is intact. The evidence-bundle
path is pure-Python and needs no sibling package at all, so an auditor can run
it on a bundle handed to them offline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional

from . import resolve


@dataclass
class ArtifactResult:
    kind: str
    ok: bool
    checked: int
    detail: str = ""
    broken_at: Optional[int] = None

    def as_dict(self) -> dict:
        return {"kind": self.kind, "ok": self.ok, "checked": self.checked,
                "detail": self.detail, "broken_at": self.broken_at}


@dataclass
class VerifyReport:
    artifacts: List[ArtifactResult] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """True when nothing was supplied to verify (distinct from a failure)."""
        return not self.artifacts

    @property
    def ok(self) -> bool:
        # an empty report is not a *positive* assertion of integrity, so ok is
        # False; callers that must distinguish "nothing to check" from "a check
        # failed" should consult `empty` (e.g. the CLI does, to avoid exiting
        # non-zero merely because no tools were installed).
        return bool(self.artifacts) and all(a.ok for a in self.artifacts)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "empty": self.empty,
                "artifacts": [a.as_dict() for a in self.artifacts]}

    def render(self) -> str:
        verdict = "OK" if self.ok else ("NOTHING TO VERIFY" if self.empty
                                        else "FAILED")
        lines = [f"integrity: {verdict} "
                 f"({len(self.artifacts)} artifact(s) checked)"]
        for a in self.artifacts:
            mark = "ok " if a.ok else "BAD"
            loc = f" (broke at seq {a.broken_at})" if a.broken_at is not None else ""
            lines.append(f"  [{mark}] {a.kind}: {a.checked} record(s){loc}"
                         + (f" — {a.detail}" if a.detail else ""))
        if not self.artifacts:
            lines.append("  (nothing supplied to verify)")
        return "\n".join(lines)


def verify_evidence_bundle(bundle: Any, secret: Optional[bytes] = None) -> ArtifactResult:
    """Verify an agentledger evidence bundle (dict or path to a JSON file).

    Pure-Python via ``agentledger.evidence.verify_bundle`` when available; that
    function needs only the bundle itself (no DB, no network). Returns an
    ArtifactResult; ``ok=False`` with a clear detail if agentledger isn't
    importable to run the check.
    """
    if isinstance(bundle, str):
        # a missing/unreadable/malformed bundle file is a normal auditor mistake;
        # report it as a failed check, never a traceback.
        try:
            with open(bundle, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
        except (OSError, ValueError) as e:
            return ArtifactResult("evidence-bundle", False, 0,
                                  f"could not read bundle: {e}")
    if not isinstance(bundle, dict):
        return ArtifactResult("evidence-bundle", False, 0,
                              "bundle is not a JSON object")
    count = int(bundle.get("entry_count", len(bundle.get("entries", []))))
    if not resolve.availability().has("agentledger"):
        return ArtifactResult("evidence-bundle", False, count,
                              "agentledger not resolvable to verify bundle")
    from agentledger.evidence import verify_bundle as _vb
    ok, broken = _vb(bundle, secret)
    detail = "chain + signatures verified offline" if ok else "verification failed"
    return ArtifactResult("evidence-bundle", ok, count, detail, broken)


def verify_recorder(recorder: Any) -> ArtifactResult:
    """Verify a live agentledger Recorder / Ledger in place."""
    ok, broken = recorder.verify()
    entries = recorder.entries()
    detail = "chain + signatures intact" if ok else "verification failed"
    return ArtifactResult("ledger", ok, len(entries), detail, broken)


def verify_warden_audit(audit: Any) -> ArtifactResult:
    """Verify a repo-warden AuditLog (hash chain)."""
    vr = audit.verify()
    return ArtifactResult("warden-audit", vr.ok, vr.checked,
                          vr.detail, vr.broken_seq)


def verify_warden_jsonl(path_or_lines: Any) -> ArtifactResult:
    """Re-walk a repo-warden JSONL audit export's BLAKE2b hash chain.

    Reproduces the chain purely from the exported rows — the property that lets
    an auditor validate an export offline. Works with a file path or an iterable
    of JSON lines.
    """
    import hashlib

    # required fields for every exported warden audit row; a row missing any of
    # these is malformed (truncated write, hand-edit) and must be reported, not
    # crash the auditor's verify.
    _REQUIRED = ("seq", "ts", "actor", "token_id", "op", "repo", "branch",
                 "force", "allowed", "rule", "reason", "prev_hash", "this_hash")
    try:
        if isinstance(path_or_lines, str):
            with open(path_or_lines, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        else:
            lines = [ln for ln in path_or_lines if ln.strip()]
    except OSError as e:
        return ArtifactResult("warden-audit-jsonl", False, 0,
                              f"could not read export: {e}")

    events = []
    for ln in lines:
        try:
            ev = json.loads(ln)
        except ValueError:
            return ArtifactResult("warden-audit-jsonl", False, len(events),
                                  "export contains a line that is not valid JSON")
        missing = [k for k in _REQUIRED if k not in ev]
        if missing:
            return ArtifactResult(
                "warden-audit-jsonl", False, len(events),
                f"row missing required field(s): {', '.join(missing)}",
                ev.get("seq"))
        events.append(ev)

    if not events:
        # an empty export is not a positive assertion of integrity
        return ArtifactResult("warden-audit-jsonl", False, 0,
                              "export is empty — nothing to verify")
    events.sort(key=lambda e: e["seq"])

    genesis = "0" * 64
    prev = genesis
    checked = 0
    for ev in events:
        payload = {
            "ts": ev["ts"], "actor": ev["actor"], "token_id": ev["token_id"],
            "op": ev["op"], "repo": ev["repo"], "branch": ev["branch"],
            "force": bool(ev["force"]), "allowed": bool(ev["allowed"]),
            "rule": ev["rule"], "reason": ev["reason"],
        }
        blob = prev + "\n" + json.dumps(payload, sort_keys=True,
                                        separators=(",", ":"))
        this_hash = hashlib.blake2b(blob.encode("utf-8"), digest_size=32).hexdigest()
        if ev["prev_hash"] != prev:
            return ArtifactResult("warden-audit-jsonl", False, checked,
                                  "prev_hash does not chain", ev["seq"])
        if this_hash != ev["this_hash"]:
            return ArtifactResult("warden-audit-jsonl", False, checked,
                                  "row contents modified after recording", ev["seq"])
        prev = ev["this_hash"]
        checked += 1
    return ArtifactResult("warden-audit-jsonl", True, checked, "chain intact")


def verify_graph_audit(graph_store: Any) -> ArtifactResult:
    """Verify a codegraph Store's hash-chained audit log."""
    ok, broken = graph_store.audit.verify()
    records = list(graph_store.audit)
    detail = "chain intact" if ok else "verification failed"
    return ArtifactResult("codegraph-audit", ok, len(records), detail, broken)


def verify_all(*, bundle: Any = None, recorder: Any = None,
               warden_audit: Any = None, warden_jsonl: Any = None,
               graph_store: Any = None, secret: Optional[bytes] = None
               ) -> VerifyReport:
    """Verify every supplied integrity artifact and return one verdict."""
    report = VerifyReport()
    if bundle is not None:
        report.artifacts.append(verify_evidence_bundle(bundle, secret))
    if recorder is not None:
        report.artifacts.append(verify_recorder(recorder))
    if warden_audit is not None:
        report.artifacts.append(verify_warden_audit(warden_audit))
    if warden_jsonl is not None:
        report.artifacts.append(verify_warden_jsonl(warden_jsonl))
    if graph_store is not None:
        report.artifacts.append(verify_graph_audit(graph_store))
    return report
