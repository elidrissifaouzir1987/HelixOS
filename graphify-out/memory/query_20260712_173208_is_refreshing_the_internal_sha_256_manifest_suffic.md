---
type: "correction"
date: "2026-07-12T17:32:08.553292+00:00"
question: "Is refreshing the internal SHA-256 manifest sufficient before PLAN-004 release evidence upload?"
contributor: "graphify"
outcome: "corrected"
correction: "Always perform semantic revalidation after the last manifest refresh and before upload; never treat a self-generated hash list as independent evidence of meaning."
source_nodes: ["tools/plan004_supply_chain.py", ".github/workflows/durable-preparation.yml"]
---

# Q: Is refreshing the internal SHA-256 manifest sufficient before PLAN-004 release evidence upload?

## Answer

No. A manifest-only final check can bless a replaced SBOM, descriptor or license inventory after rehashing. The final verifier now re-parses and cross-checks the exact Cargo production closure, CycloneDX references/native edge, resolved bundled SQLite features, license and SPDX inventories, reviewed input hashes, RustSec identity/count, runner/workflow provenance, local-only M4 labels and the exact-commit removal report. A deliberate empty-SBOM replacement followed by manifest refresh is rejected.

## Outcome

- Signal: corrected
- Correction: Always perform semantic revalidation after the last manifest refresh and before upload; never treat a self-generated hash list as independent evidence of meaning.

## Source Nodes

- tools/plan004_supply_chain.py
- .github/workflows/durable-preparation.yml