# Demos

Five runnable scenarios in [`../demos/`](../demos/), each aimed at a different
audience, each exercising the **real APIs** of the suite tools. They run fully
offline. Each scenario resolves the suite packages on its own — from whatever is
installed (what CI does) or from sibling source checkouts next to this repo
(`../agentledger`, `../sentinel-policy`, …) — and any tool that can't be
resolved is skipped with a note rather than crashing. Every scenario exits `0`.

```bash
python demos/run_all.py                       # all five, end to end
python demos/01_end_to_end_accountability.py  # or just one
```

> On a cp1252 Windows console, run with `PYTHONUTF8=1`.

| # | Scenario | Audience | What it shows | Tools exercised |
|---|----------|----------|---------------|-----------------|
| 1 | [End-to-end accountability](../demos/01_end_to_end_accountability.py) | CTOs / engineering leaders | A directive flows policy → signed ledger → scoped git op → offline-verifiable evidence bundle. The headline claim, executed. | sentinel-policy, agentledger, repo-warden |
| 2 | [Tamper-evidence & refusal](../demos/02_tamper_evidence_and_refusal.py) | Security | Hash-chain catches a row edited directly in the DB (S4); a denied action leaves a recorded refusal (S7); a scoped token is namespace-bound and revoked instantly (S2). | sentinel-policy, agentledger, repo-warden |
| 3 | [Compliance evidence](../demos/03_compliance_evidence.py) | Compliance / audit | m-of-n independent approvals clear a gated high-risk action (S3); a key rotation keeps a continuity proof; the whole record exports as one file a regulator verifies offline. | sentinel-policy, agentledger |
| 4 | [Governed git access](../demos/04_governed_git_access.py) | Platform engineering | RFC 8628 device-flow grant for a headless agent, then the same scoped token enforced against a branch-protection policy (protected branch, force-push, namespace). | repo-warden |
| 5 | [Inspectable agent loop](../demos/05_inspectable_agent_loop.py) | AI agent builders | A cyclework refine loop runs to convergence with a full trace; codegraph-mcp grounds an edit with a structural, audited read of code it never trained on. | cyclework, codegraph-mcp |

## The SENTINEL rules the demos lean on

| Rule | Name | Seen in |
|------|------|---------|
| S2 | Least Authority | 1, 2 |
| S3 | Gated Escalation | 1, 3 |
| S4 | Immutable Record | 2 |
| S6 | Boundary Integrity | 2 |
| S7 | Provable Refusal | 2 |

---

Each demo prints clear, narrated output and exits `0`, so they double as smoke
tests — [`tests/`](../tests/) covers that the demos import and run cleanly.
