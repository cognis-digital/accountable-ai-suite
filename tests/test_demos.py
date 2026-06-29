"""Smoke tests for the suite demos and the end-to-end integration example.

The suite is an umbrella over five sibling packages; this repo ships no package
of its own. These tests confirm that the bundled demos and the integration
example import and run cleanly (the same paths CI exercises), resolving the
suite packages from the environment or from sibling source checkouts.
"""
import importlib
import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")
sys.path.insert(0, DEMOS)

DEMO_MODULES = [
    "01_end_to_end_accountability",
    "02_tamper_evidence_and_refusal",
    "03_compliance_evidence",
    "04_governed_git_access",
    "05_inspectable_agent_loop",
]


def _have(module: str) -> bool:
    """Is a suite package resolvable (incl. via sibling checkout)?"""
    from _common import AVAILABLE  # noqa: WPS433 - import after sys.path set up
    return AVAILABLE.get(module, False)


def test_common_resolves_something():
    """The resolver runs and reports a status for every suite module."""
    from _common import AVAILABLE
    assert set(AVAILABLE) == {
        "agentledger", "sentinel_policy", "repo_warden", "codegraph", "cyclework"
    }


@pytest.mark.parametrize("name", DEMO_MODULES)
def test_demo_runs_and_exits_clean(name, capsys):
    """Each demo's main() runs without raising and prints its banner."""
    mod = importlib.import_module(name)
    mod.main()  # must not raise; demos skip missing tools rather than crashing
    out = capsys.readouterr().out
    assert "=" * 10 in out  # the rule() banner was printed


def test_integration_example_runs():
    """examples/integration.py runs end to end when the gov packages are present."""
    # ensure sibling packages are on path the same way the demos do
    import _common  # noqa: F401  (side effect: puts siblings on sys.path)
    if not (_have("agentledger") and _have("sentinel_policy") and _have("repo_warden")):
        pytest.skip("governance packages not all resolvable in this environment")
    path = os.path.join(REPO_ROOT, "examples", "integration.py")
    spec = importlib.util.spec_from_file_location("suite_integration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()  # prints and returns; raises if the chain doesn't verify
