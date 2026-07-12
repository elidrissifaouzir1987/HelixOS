---
type: "query"
date: "2026-07-12T15:39:27.567242+00:00"
question: "What did the hosted PLAN-004 rerun prove after the Windows restore reachability correction?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["process_crash.rs", "production_restore_conformance.rs", "restore_maintenance_api.rs", "ci-remediation-local.md"]
---

# Q: What did the hosted PLAN-004 rerun prove after the Windows restore reachability correction?

## Answer

Run 29198018266 passed at exact source 2720fbe1042095d74db65f3d3fe71244cf38c810 on macOS arm64, Linux x86_64, and Windows x64. The frozen registry remained 123 boundaries and 167 cases. macOS and Linux executed all 167 process-kill cases; Windows separately passed the public RESTORE_PLATFORM_UNSUPPORTED refusal and executed the exact remaining 150 production-reachable cases. The Windows process-kill executable passed 5 tests in 26.28 seconds. This is pull-request validation, not immutable or production restore evidence.

## Outcome

- Signal: useful

## Source Nodes

- process_crash.rs
- production_restore_conformance.rs
- restore_maintenance_api.rs
- ci-remediation-local.md