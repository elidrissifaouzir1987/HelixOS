---
type: "ci-diagnosis"
date: "2026-07-16T16:49:33.100092+00:00"
question: "Why did PR #8 PLAN-005 supply-chain release evidence fail after PLAN-006 Phase 1 workspace setup?"
contributor: "graphify"
outcome: "corrected"
correction: "Bind the two full-lock-derived digests to the reviewed 224-record lockfile and compare the live graph directly; preserve all selected production closure oracles."
source_nodes: ["plan005_supply_chain.py", "Plan005SupplyChainTests"]
---

# Q: Why did PR #8 PLAN-005 supply-chain release evidence fail after PLAN-006 Phase 1 workspace setup?

## Answer

The four local PLAN-006 workspace packages increased kernel/Cargo.lock from 220 to 224 records. The selected PLAN-005 production closure remained exactly 84 packages, 143 dependency edges and 77 external packages, while the pinned RustSec scan still reported zero vulnerabilities and only RUSTSEC-2025-0134. The exact RustSec report digest and production-graph artifact digest bind the full lockfile, so both must be repinned to the reviewed current lock without changing package, edge, license or SBOM oracles.

## Outcome

- Signal: corrected
- Correction: Bind the two full-lock-derived digests to the reviewed 224-record lockfile and compare the live graph directly; preserve all selected production closure oracles.

## Source Nodes

- plan005_supply_chain.py
- Plan005SupplyChainTests