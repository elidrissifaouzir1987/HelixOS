---
type: "query"
date: "2026-07-12T12:46:53.604765+00:00"
question: "Which final immutable evidence closed PLAN-001 T028 and the later PLAN-003 T069 correction?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["PLAN-001", "T028", "T069", "conformance/catalog.yaml"]
---

# Q: Which final immutable evidence closed PLAN-001 T028 and the later PLAN-003 T069 correction?

## Answer

The unchanged commit b3132586245acea415104381b337d3fea3303444 passed the hosted Linux x86_64, macOS arm64 and Windows x64 PLAN-001 workspace matrix in workflow-dispatch run 29192812460; all three retained ZIP digests matched independent downloads and SLSA attestations. The same commit passed the three-host PLAN-003 pull-request matrix in run 29192809998, including both Windows concurrent-initializer regressions, closing T069. T028 closes only the hosted matrix: Linux arm64, physical Mac mini M4, the ignored 100,000-envelope soak in CI, Tier 1 and production readiness remain pending, so PLAN-001 stays pending-evidence.

## Outcome

- Signal: useful

## Source Nodes

- PLAN-001
- T028
- T069
- conformance/catalog.yaml