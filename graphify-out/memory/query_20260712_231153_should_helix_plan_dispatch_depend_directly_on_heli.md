---
type: "implementation-correction"
date: "2026-07-12T23:11:53.712079+00:00"
question: "Should helix-plan-dispatch depend directly on helix-plan-preparation during PLAN-005 setup?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep PLAN-005 orchestration on its own traits and dispatch contract crate; do not broaden the frozen PLAN-004 consumer graph."
source_nodes: ["helix-plan-dispatch", "helix-plan-preparation", "portability.rs"]
---

# Q: Should helix-plan-dispatch depend directly on helix-plan-preparation during PLAN-005 setup?

## Answer

No. The first setup attempt added that edge and the frozen PLAN-004 portability allowlist rejected the extra consumer. The direct dependency and feature forwarding were removed. Final helix-plan-dispatch direct dependencies are only getrandom and helix-dispatch-contracts, and the protected portability suite passes 8 of 8.

## Outcome

- Signal: corrected
- Correction: Keep PLAN-005 orchestration on its own traits and dispatch contract crate; do not broaden the frozen PLAN-004 consumer graph.

## Source Nodes

- helix-plan-dispatch
- helix-plan-preparation
- portability.rs