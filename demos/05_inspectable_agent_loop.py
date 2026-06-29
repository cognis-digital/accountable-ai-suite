"""Scenario 5 - AI agent builders: an inspectable loop over a no-train graph.

Two of the suite's tools are about the agent's own machinery rather than the
governance around it:

  * cyclework makes the agent's propose -> check -> revise loop a first-class
    object you can inspect, with convergence/plateau detection and a full trace
    -- instead of a `while True` nobody can audit.
  * codegraph-mcp gives the agent real structural understanding of code it is
    NEVER trained on, served locally, with an audit row for every read.

This demo runs a real cyclework refinement to convergence and (if codegraph is
checked out) shows the kind of grounded, audited read an agent makes before it
acts. Both run fully offline.
"""
from _common import rule, require, suite_status


def main() -> None:
    rule("INSPECTABLE AGENT LOOP  -  cyclework refinement + no-train code reads")
    suite_status()

    # ---- cyclework: a self-correcting loop you can inspect --------------
    if require("cyclework"):
        from cyclework import Engine, Verdict

        target = 0.0

        def check(x: float) -> Verdict:
            err = abs(x - target)
            # higher-is-better score; ok once we're within tolerance
            return Verdict(ok=err < 1e-6, score=-err,
                           feedback=f"off by {err:.4f}", detail={"x": x})

        def revise(x: float, v: Verdict) -> float:
            # crude gradient-free step toward the target, using the feedback
            return x - 0.5 * (x - target)

        engine = Engine(check, revise, max_iterations=40, patience=8, min_delta=1e-9)
        result = engine.run(10.0)

        print(f"\ncyclework loop: status={result.status.name} after "
              f"{result.iterations} iteration(s)")
        print(f"   final state={result.state:.6g}  best score={result.best.score:.6g}")
        print("   trace (first 5 iterations):")
        for it in result.history[:5]:
            print(f"     i={it.index}  x={it.state:.5f}  ok={it.verdict.ok}  "
                  f"score={it.verdict.score:.5f}  '{it.verdict.feedback}'")
        print("   ...the loop is an object: every step's state, verdict and score is recorded.")

    # ---- codegraph: structural understanding of code never trained on ----
    if require("codegraph") and _codegraph_is_suite():
        import os, tempfile
        from _common import _SUITE_PARENT
        from codegraph.graph import Store
        from codegraph.indexer import index_path

        sample = os.path.join(_SUITE_PARENT, "codegraph-mcp", "examples", "sample_repo")
        if os.path.isdir(sample):
            db = os.path.join(tempfile.mkdtemp(prefix="suite_demo_"), "graph.db")
            store = Store(db)
            index_path(store, sample)
            hits = store.search_symbols("loadUser", None, 1)
            print("\ncodegraph: an agent grounds an edit by reading the graph (not the weights):")
            if hits:
                sym = hits[0]
                blast = store.impact(sym.id)
                print(f"   search_symbols('loadUser') -> {sym.name} [{sym.lang}] "
                      f"{sym.path}:{sym.start_line}")
                print(f"   impact({sym.id}) -> blast radius of {blast['impacted_count']} symbol(s) "
                      "the agent must not break")
            # every read landed in the hash-chained audit log
            tail = store.audit.tail(3) if hasattr(store, "audit") else []
            if tail:
                print(f"   each read was logged; audit tail head hash {tail[-1].hash[:12]}...")
            store.close()
        else:
            print("\ncodegraph: sample repo not found next to checkout; skipping graph read.")

    print("\nThe loop is inspectable and the code understanding is grounded, local, and audited.")


def _codegraph_is_suite() -> bool:
    """True only if the importable `codegraph` is the suite's MCP graph.

    A few unrelated packages also publish the name `codegraph`; this guards
    against importing one of those by accident.
    """
    try:
        from codegraph.graph import Store  # noqa: F401
        from codegraph.indexer import index_path  # noqa: F401
        return True
    except Exception:
        print("\ncodegraph: the suite's codegraph-mcp isn't resolvable here "
              "(an unrelated 'codegraph' may be installed); skipping graph read.")
        return False


if __name__ == "__main__":
    main()
