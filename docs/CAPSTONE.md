# The capstone layer (`accountable_suite`)

The five suite tools stand alone. This repo now also ships a small **capstone
package** — [`accountable_suite`](../accountable_suite/) — that is the *umbrella
made executable*: it wires the tools into one accountable path and adds the
cross-tool capabilities that only make sense across all of them at once.

It is stdlib-only and dependency-light. The five tools it orchestrates are
**optional**: install any subset and every capability degrades gracefully for
the ones you skip (this is exactly how it runs in CI, which installs four of the
five). Tools are resolved from the environment first, then from sibling
checkouts next to this repo — fully offline.

```bash
pip install -e .            # installs the `suite` CLI
pip install -e '.[governance]'   # + the four governance tools from source
```

## What it adds

### 1. `Orchestrator` — the whole path in one call

```python
from accountable_suite import Orchestrator
from repo_warden import Store

ws = Store()
token, _ = ws.issue_token("agent:dev", {"branch:push"}, "acme/*")

orch = Orchestrator(policy=my_policy, warden_store=ws)   # + optional graph_store
outcome = orch.act(
    actor="agent:dev", action="push",
    params={"repo": "acme/api", "branch": "feature/x"}, token=token,
    ground_symbol="loadUser",       # optional: attach code-graph blast radius
)
# outcome.allowed, outcome.policy_rule, outcome.warden_rule, outcome.graph_facts …

ok, broken = orch.verify()
bundle = orch.export_evidence("evidence.json")   # offline-verifiable
```

`act()` runs, in order: **sentinel-policy decides → agentledger signs & chains
the decision → repo-warden scopes the git op → (optional) codegraph grounds the
change**. A denied policy or a denied warden decision is a normal, *recorded*
outcome (SENTINEL S7), never an exception. Missing a tool? That leg is scoped
down with a note instead of crashing.

### 2. `build_report` — a unified compliance report

One document over all five tools, rendered as **Markdown / HTML / SARIF / JSON**:

```python
from accountable_suite import build_report
rpt = build_report(policy=policy, recorder=orch.recorder,
                   warden_audit=audit_log, graph_store=graph)
open("report.html", "w").write(rpt.to_html())
open("findings.sarif", "w").write(rpt.to_sarif())   # GitHub code scanning
```

It aggregates policy doctrine coverage, ledger integrity + evidence head, warden
authorization denials, and the code graph's shape — and turns **doctrine gaps
and denied authorizations into SARIF findings** a machine can gate on.

### 3. `verify_all` — one integrity verdict across every artifact

```python
from accountable_suite import verify_all
report = verify_all(recorder=orch.recorder, warden_audit=audit_log,
                    graph_store=graph)          # or: bundle="evidence.json"
print(report.render())        # per-artifact breakdown; report.ok is the verdict
```

Re-walks the agentledger evidence bundle (hash chain + Ed25519 signatures + key
continuity), the repo-warden audit chain, and the codegraph audit chain. The
**evidence-bundle path is pure Python** — it validates a bundle handed to an
auditor offline, with no access to the systems that produced it, and *locates*
the first tampered record.

### 4. `build_scorecard` — a governance maturity scorecard

Five dimensions (one per SENTINEL concern the suite addresses), each scored
0–100 from **live signals** rather than a questionnaire, mapped to a maturity
level (*Absent / Initial / Managed / Governed*). Every point is traceable to a
signal you can reproduce.

### 5. The `suite` CLI

```bash
suite status                       # which tools are resolvable
suite scorecard [--json]           # governance maturity scorecard
suite report --format html -o report.html
suite verify  --bundle evidence.json
suite demo    [--format markdown]  # run the reference scenario end to end
```

With nothing supplied, `scorecard`/`report`/`demo` build a small **real**
governed-agent scenario so the commands always exercise whatever is installed.

## The reference governed agent

[`examples/governed_agent.py`](../examples/governed_agent.py) is the shape to
copy: an agent that *cannot act except through the orchestrator*. It reads logs,
grounds a change against the graph, pushes to a feature branch, is refused a
push to `main`, and is refused an exfiltration attempt — each a single `act()`
call, all on one signed, offline-verifiable ledger.

## Verified, not claimed

The capstone is covered by [`tests/test_capstone.py`](../tests/test_capstone.py)
(orchestrator, report in every format, scorecard, offline + tamper verification,
and the CLI) and its three demos (6–8) run in [`demos/run_all.py`](../demos/run_all.py).
Tests that need a given tool skip cleanly when it isn't installed, so the same
suite is green whether you have all five tools or four.
