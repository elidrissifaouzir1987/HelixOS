---
type: "query"
date: "2026-07-15T01:19:05.780008+00:00"
question: "PLAN-005 T094: what corrected the pre-release removal-manifest pin drift?"
contributor: "graphify"
outcome: "corrected"
correction: "Bind every active release/removal consumer to the authoritative current manifest digest and add a test that compares the supply constant directly with the removal-driver constant; do not rewrite historical evidence."
source_nodes: ["plan005_supply_chain.py", "portability.rs", "removal-protected-files.json"]
---

# Q: PLAN-005 T094: what corrected the pre-release removal-manifest pin drift?

## Answer

Expanded from graph vocabulary via tasks, immutable, workflow, evidence, protected and removal. The T094 pre-release audit found that active supply-chain and Rust portability checks still pinned the prior removal-manifest digest while the authoritative manifest, removal driver, policy test and US4 evidence use the current digest 090cb94b6cf3c5c3f005931ef22635558a18e689c171b690010955e1125f4cf8. Both active pins were updated, the Python policy suite now asserts supply and removal pins are identical, and validation passed: Python 36/36, Rust portability 7/7, and a fresh supply build plus verify. Historical immutable benchmark evidence retaining the old run digest was not rewritten.

## Outcome

- Signal: corrected
- Correction: Bind every active release/removal consumer to the authoritative current manifest digest and add a test that compares the supply constant directly with the removal-driver constant; do not rewrite historical evidence.

## Source Nodes

- plan005_supply_chain.py
- portability.rs
- removal-protected-files.json