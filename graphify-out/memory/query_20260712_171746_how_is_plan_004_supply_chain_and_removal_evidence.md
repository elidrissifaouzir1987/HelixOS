---
type: "implementation"
date: "2026-07-12T17:17:46.652318+00:00"
question: "How is PLAN-004 supply-chain and removal evidence made fail-closed?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["tools/plan004_supply_chain.py", "tools/plan004_removal_drill.py", ".github/workflows/durable-preparation.yml", "specs/004-durable-preparation/evidence/README.md"]
---

# Q: How is PLAN-004 supply-chain and removal evidence made fail-closed?

## Answer

The release workflow pins cargo-cyclonedx 0.5.9, cargo-audit 0.22.2, one RustSec database revision and one SPDX license-list revision. tools/plan004_supply_chain.py rekeys machine-local CycloneDX references, verifies the 77-component production closure including Windows and bundled SQLite, retains 73 external license inventories/texts, the locked native crate/source, complete RustSec output, provenance, local-only M4 labels and a sorted internal manifest. A separate job resolves each of four upload-artifact digests through the current-run API before attestation. tools/plan004_removal_drill.py uses an isolated exact-commit worktree, restores the frozen pre-feature lock, removes Feature 004 and runs the six-package prerequisite/legacy default suites while protecting 146 files. Local integration and 17 unit tests pass; immutable workflow-dispatch evidence is still pending.

## Outcome

- Signal: useful

## Source Nodes

- tools/plan004_supply_chain.py
- tools/plan004_removal_drill.py
- .github/workflows/durable-preparation.yml
- specs/004-durable-preparation/evidence/README.md