# Accountable AI Engineering

**The open suite for teams who have to *prove* their AI agents are under control — on infrastructure they own, with code that never leaves it.**

---

Answer honestly:

- Do your AI agents need to read and reason over **proprietary code that legally cannot be sent to someone else's cloud**?
- When an agent takes an action, can you say **who authorized it** — and prove it to an auditor **months later, offline**?
- Would your compliance team rather have **a signed, tamper-evident record** than a screenshot and a shrug?
- Do you want governance that's a **rule you can enforce**, not a slogan in a marketing deck?

If you nodded at even one of those, you're exactly who this is built for — and you can be running the relevant piece in about five minutes.

## Start where it hurts

Each tool stands on its own. Pick the pain you have today and go straight to it:

| Your problem right now | Reach for | 
|---|---|
| "Agents need to understand our codebase, but it can't leave the building." | → **[codegraph-mcp](https://github.com/cognis-digital/codegraph-mcp)** |
| "We can't prove who authorized an agent's action." | → **[agentledger](https://github.com/cognis-digital/agentledger)** |
| "'Responsible AI' is a slogan here, not something we can enforce." | → **[sentinel-policy](https://github.com/cognis-digital/sentinel-policy)** |
| "Agents and humans push to the same repos with no guardrails." | → **[repo-warden](https://github.com/cognis-digital/repo-warden)** |
| "Our agent's reasoning loop is a `while` nobody can inspect." | → **[cyclework](https://github.com/cognis-digital/cyclework)** |

Each is `pip install` away, Apache-2.0, dependency-light, and runs on hardware you control. Solve one problem today; the pieces are built to snap together when you're ready for the rest.

## What you get

| Tool | What it does | Why it wins |
|------|--------------|-------------|
| [**codegraph-mcp**](https://github.com/cognis-digital/codegraph-mcp) | No-train code knowledge graph served to agents over MCP | Real structural code understanding — **6 languages, cross-language** — with an audit row for every read. Overlays the repos you already host; nothing is trained on. |
| [**agentledger**](https://github.com/cognis-digital/agentledger) | Signed, hash-chained flight recorder for agent directives | Prove who authorized every action. **Ed25519 · post-quantum ML-DSA · hybrid**, key-rotation continuity proofs, evidence bundles a regulator verifies offline. |
| [**sentinel-policy**](https://github.com/cognis-digital/sentinel-policy) | Open governance doctrine + policy-gate engine | The **SENTINEL seven rules** plus a data-only engine that returns allow / deny / require-approval, each decision citing the rule it serves. |
| [**repo-warden**](https://github.com/cognis-digital/repo-warden) | Git access governance over existing remotes | RFC 8628 device-flow auth, scoped revocable tokens, branch protection as a drop-in `pre-receive` hook. No forge migration. |
| [**cyclework**](https://github.com/cognis-digital/cyclework) | Iterative refinement engine | The propose → check → revise loop as a first-class, inspectable object — for solvers, optimizers, and self-correcting agent loops. |

## How the pieces compose

Together they form one accountable path from an operator's intent to an agent's action against your code — and a tamper-evident record of all of it:

```mermaid
flowchart LR
    OP([Operator / Agent]) -->|directive| SP[sentinel-policy\nevaluate against doctrine]
    SP -->|allow / deny / approve| AL[agentledger\nsign + hash-chain the decision]
    AL -->|authorized| RW[repo-warden\nscope the git operation]
    RW -->|read code| CG[codegraph-mcp\nknowledge graph over MCP]
    CG -->|every read logged| AL
    AL -->|offline-verifiable| EV([Evidence bundle\nfor a regulator])
```

A policy *decides*, the ledger *proves*, the warden *scopes*, the graph *informs* — and at any moment you export evidence a third party can verify with no access to your systems. Want to see it run end to end? It's one file: **[`examples/integration.py`](examples/integration.py)** (and our CI installs all three governance packages from source and runs it on every commit, so "they compose" is verified, not claimed).

## How it compares

Built for the regulated, high-stakes case — defense, finance, healthcare, government — where the cloud assistants aren't allowed and the self-hosted forges leave the audit story on a roadmap.

| | Cloud assistants | Self-hosted forge | **This suite** |
|---|---|---|---|
| Code leaves your machine | yes | no | **no** |
| Used to train a model | often | sometimes | **never** |
| Requires migrating your hosting | no | yes | **no — overlays existing repos** |
| Tamper-evident audit of agent actions | no | roadmap | **shipped** |
| Cross-language code dependency graph | partial | 2 languages | **6 languages** |
| Post-quantum signing | — | roadmap | **shipped (ML-DSA-65 + hybrid)** |
| Key rotation with continuity proofs | — | — | **shipped** |
| Published, reproducible benchmark | — | none | **yes** |
| Runs air-gapped | no | heavy | **standard library + SQLite** |

## Why teams choose it

- **No training, ever.** Nothing here ingests your code to rank, sell, or train a model.
- **Overlay, not migration.** Point the tools at the repos and remotes you already run.
- **Provable, offline.** Hash-chained ledgers, cryptographic signatures, and evidence bundles a regulator can verify with no call back to any vendor.
- **Boring on purpose.** Small, readable, dependency-light Python + SQLite — easy to vet, easy to run in a restricted network.

## Get started

```bash
pip install -e .   # inside any of the five repos
```

Pick your entry point from **[Start where it hurts](#start-where-it-hurts)** and follow it into the repo. Each one ships with a runnable demo and a green test suite.

## License

Apache-2.0. © Cognis Digital. Every tool — including the SENTINEL governance doctrine — is published openly, so you can argue with the rules on their merits before you ever adopt them.
