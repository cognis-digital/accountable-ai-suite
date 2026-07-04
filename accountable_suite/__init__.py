"""accountable_suite — the capstone layer over the five accountable-AI tools.

The five suite tools (sentinel-policy, agentledger, repo-warden, codegraph-mcp,
cyclework) each stand alone. This package is the *umbrella*: it wires them into
one accountable path and adds the cross-tool capabilities that only make sense
across all of them at once:

  * ``Orchestrator``       — policy -> signed ledger -> warden git-op ->
                             evidence bundle, in a single ``act()`` call.
  * ``build_report``       — a unified compliance report (Markdown / HTML /
                             SARIF / JSON) aggregating every tool.
  * ``build_scorecard``    — a governance maturity / coverage scorecard.
  * ``verify_all``         — one integrity check across every artifact the suite
                             can produce (evidence bundle, warden audit, graph
                             audit), including a pure-Python offline bundle check.

Nothing is vendored: the sibling tools are resolved from the environment or from
sibling checkouts (see ``resolve``), and every capability degrades gracefully
when a tool is absent, so this works in CI where only some are installed.
"""
from __future__ import annotations

from . import resolve, scorecard, report, verify, orchestrator
from .resolve import availability, require
from .orchestrator import Orchestrator, Outcome
from .scorecard import Scorecard, Dimension, build_scorecard
from .report import ComplianceReport, Finding, build_report
from .verify import VerifyReport, ArtifactResult, verify_all

__version__ = "0.1.0"
__all__ = [
    "availability", "require",
    "Orchestrator", "Outcome",
    "Scorecard", "Dimension", "build_scorecard",
    "ComplianceReport", "Finding", "build_report",
    "VerifyReport", "ArtifactResult", "verify_all",
    "resolve", "scorecard", "report", "verify", "orchestrator",
    "__version__",
]
