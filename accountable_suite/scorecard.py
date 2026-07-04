"""A governance maturity / coverage scorecard for the suite.

Answers, in one machine-checkable object: *how much of the accountable path do
you actually have stood up, and how well?* It scores five dimensions — one per
SENTINEL concern the suite addresses — from concrete, live signals rather than a
questionnaire:

  * Attribution & policy (S1/S3)  — is a policy present and valid, and how much
    of the SENTINEL doctrine does it cite?
  * Immutable record (S4)         — is agentledger present, and does the ledger
    (if one is supplied) verify?
  * Provable refusal (S7)         — are denied directives actually recorded?
  * Least authority (S2)          — is repo-warden present and its audit intact?
  * Grounded understanding        — is a no-train code graph available to ground
    agent reads?

Each dimension yields 0..100; the overall score is their mean, mapped to a
maturity level (Absent / Initial / Managed / Governed). It is deliberately
transparent: every point is traceable to a signal you can reproduce.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import resolve

LEVELS = [
    (0, "Absent"),
    (25, "Initial"),
    (50, "Managed"),
    (80, "Governed"),
]


def _level_for(score: float) -> str:
    name = LEVELS[0][1]
    for threshold, label in LEVELS:
        if score >= threshold:
            name = label
    return name


@dataclass
class Dimension:
    key: str
    title: str
    score: float                    # 0..100
    doctrine: List[str]
    signals: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"key": self.key, "title": self.title,
                "score": round(self.score, 1), "doctrine": self.doctrine,
                "signals": self.signals}


@dataclass
class Scorecard:
    dimensions: List[Dimension]
    tools_present: Dict[str, bool]

    @property
    def overall(self) -> float:
        if not self.dimensions:
            return 0.0
        return sum(d.score for d in self.dimensions) / len(self.dimensions)

    @property
    def level(self) -> str:
        return _level_for(self.overall)

    def as_dict(self) -> dict:
        return {
            "overall": round(self.overall, 1),
            "level": self.level,
            "tools_present": self.tools_present,
            "dimensions": [d.as_dict() for d in self.dimensions],
        }

    def render(self) -> str:
        lines = [f"Governance maturity: {self.level} ({self.overall:.0f}/100)", ""]
        bar_w = 20
        for d in self.dimensions:
            filled = int(round(d.score / 100 * bar_w))
            bar = "#" * filled + "-" * (bar_w - filled)
            cite = f" [{','.join(d.doctrine)}]" if d.doctrine else ""
            lines.append(f"  {d.title:<26} {bar} {d.score:5.0f}{cite}")
            for s in d.signals:
                lines.append(f"      - {s}")
        return "\n".join(lines)


def build_scorecard(*, policy: Any = None, ledger_verifies: Optional[bool] = None,
                    refusals_recorded: Optional[bool] = None,
                    warden_audit_ok: Optional[bool] = None,
                    graph_available: Optional[bool] = None) -> Scorecard:
    """Assemble a scorecard from whatever live signals the caller can supply.

    Every argument is optional; unknown signals fall back to
    tool-presence-based scoring so a scorecard is always producible. Pass a
    ``sentinel_policy.Policy`` to score doctrine coverage precisely; pass the
    boolean live-check results (ledger verify, refusal presence, warden audit
    verify) to reward a system that is not just installed but *working*.
    """
    av = resolve.availability()
    present = av.as_dict()
    dims: List[Dimension] = []

    # ---- S1/S3: attribution & policy -----------------------------------
    sig: List[str] = []
    if not av.has("sentinel_policy"):
        score = 0.0
        sig.append("sentinel-policy not resolvable")
    elif policy is None:
        score = 30.0
        sig.append("engine present but no policy supplied to score")
    else:
        problems = policy.validate()
        cov = policy.doctrine_coverage()
        covered, total = len(cov["covered"]), 7
        cov_pct = 100.0 * covered / total
        valid_bonus = 40.0 if not problems else 0.0
        # 60% weight on coverage, 40% on being valid
        score = 0.6 * cov_pct + valid_bonus
        sig.append(f"policy '{policy.name}' cites {covered}/{total} doctrine rules")
        sig.append("policy validates cleanly" if not problems
                   else f"policy has {len(problems)} validation problem(s)")
    dims.append(Dimension("policy", "Attribution & policy", min(score, 100.0),
                          ["S1", "S3"], sig))

    # ---- S4: immutable record ------------------------------------------
    sig = []
    if not av.has("agentledger"):
        score = 0.0
        sig.append("agentledger not resolvable")
    else:
        score = 50.0
        sig.append("signed, hash-chained ledger available")
        if ledger_verifies is True:
            score = 100.0
            sig.append("supplied ledger verifies (chain + signatures intact)")
        elif ledger_verifies is False:
            score = 20.0
            sig.append("supplied ledger FAILED verification")
    dims.append(Dimension("record", "Immutable record", score, ["S4"], sig))

    # ---- S7: provable refusal ------------------------------------------
    sig = []
    if not av.has("agentledger"):
        score = 0.0
        sig.append("agentledger not resolvable")
    elif refusals_recorded is True:
        score = 100.0
        sig.append("denied directives are recorded, not silently dropped")
    elif refusals_recorded is False:
        score = 40.0
        sig.append("no recorded refusal observed in the supplied ledger")
    else:
        score = 60.0
        sig.append("refusal recording is supported (no live sample supplied)")
    dims.append(Dimension("refusal", "Provable refusal", score, ["S7"], sig))

    # ---- S2: least authority (repo-warden) -----------------------------
    sig = []
    if not av.has("repo_warden"):
        score = 0.0
        sig.append("repo-warden not resolvable")
    else:
        score = 55.0
        sig.append("scoped, revocable git access available")
        if warden_audit_ok is True:
            score = 100.0
            sig.append("warden audit log verifies (chain intact)")
        elif warden_audit_ok is False:
            score = 20.0
            sig.append("warden audit log FAILED verification")
    dims.append(Dimension("scope", "Least authority", score, ["S2"], sig))

    # ---- grounded understanding (codegraph) ----------------------------
    # three states, so the score never overstates what was actually shown:
    #   True  -> a real graph was evaluated (full credit)
    #   None  -> codegraph is importable but no graph was supplied (capability
    #            only, partial credit — mirrors the report body's "not evaluated")
    #   False -> codegraph not resolvable (no credit)
    sig = []
    if graph_available is True:
        score = 100.0
        sig.append("no-train code knowledge graph evaluated for grounding")
    elif graph_available is None and av.has("codegraph"):
        score = 60.0
        sig.append("codegraph-mcp available but no graph supplied to evaluate")
    elif graph_available is None:
        score = 0.0
        sig.append("codegraph-mcp not resolvable")
    elif graph_available:
        score = 100.0
        sig.append("no-train code knowledge graph available for grounding")
    else:
        score = 0.0
        sig.append("codegraph-mcp not resolvable")
    dims.append(Dimension("grounding", "Grounded understanding", score, [], sig))

    return Scorecard(dims, present)
