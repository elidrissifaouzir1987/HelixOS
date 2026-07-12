---
type: "correction"
date: "2026-07-12T17:39:20.990510+00:00"
question: "How must cargo-cyclonedx volatility and dependency topology be handled in PLAN-004 evidence?"
contributor: "graphify"
outcome: "corrected"
correction: "Normalize volatile generator metadata and validate complete dependency adjacency, not only component/ref coverage."
source_nodes: ["tools/plan004_supply_chain.py", "tools/tests/test_plan004_evidence.py"]
---

# Q: How must cargo-cyclonedx volatility and dependency topology be handled in PLAN-004 evidence?

## Answer

Even with a pinned generator, an SBOM may carry a UUID/timestamp and a node-complete graph can still omit dependency edges. PLAN-004 now removes generator serial/timestamp metadata, rekeys workspace references, and compares every retained normal/build dependency edge against the exact cargo metadata closure, with only the reviewed libsqlite3-sys to bundled SQLite native edge added. The exact 77-package bundle passes; a deliberately emptied dependency adjacency is rejected.

## Outcome

- Signal: corrected
- Correction: Normalize volatile generator metadata and validate complete dependency adjacency, not only component/ref coverage.

## Source Nodes

- tools/plan004_supply_chain.py
- tools/tests/test_plan004_evidence.py