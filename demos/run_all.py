"""Run every suite demo scenario end to end.

    python demos/run_all.py

Each scenario is independent and resolves the suite packages on its own (from
the environment, or from sibling source checkouts next to this repo), so they
can be run in any order or on their own. Every scenario exits 0; a scenario
whose tools aren't available prints a skip note rather than failing.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_end_to_end_accountability",
    "02_tamper_evidence_and_refusal",
    "03_compliance_evidence",
    "04_governed_git_access",
    "05_inspectable_agent_loop",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
