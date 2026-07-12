---
type: "query"
date: "2026-07-12T15:18:10.882039+00:00"
question: "How should the PLAN-004 process-kill matrix honor the Windows restore platform refusal?"
contributor: "graphify"
outcome: "corrected"
correction: "Distinguish the hidden probe helper from the public Windows production entry: private helper reachability must not be promoted to Windows restore support; preserve the full registry while partitioning only release execution."
source_nodes: ["process_crash.rs", "production_restore_conformance.rs", "restore_maintenance_api.rs", "maintenance.rs"]
---

# Q: How should the PLAN-004 process-kill matrix honor the Windows restore platform refusal?

## Answer

Expanded from graph vocabulary: windows process crash restore platform unsupported boundary registry production probe refusal maintenance. Keep the frozen 123-boundary and 167-case registry unchanged. Because the public Windows v1 restore contract returns RESTORE_PLATFORM_UNSUPPORTED before package capture, PAUSE, or destination mutation, the release executor excludes exactly the 14 restore boundary IDs expanding to 17 cases and runs the remaining 150 Windows cases. macOS and Linux still run all 167. Separate runtime and source-order tests prove the refusal. Local ordinary, release, formatting, and strict Clippy gates passed; hosted rerun remains pending.

## Outcome

- Signal: corrected
- Correction: Distinguish the hidden probe helper from the public Windows production entry: private helper reachability must not be promoted to Windows restore support; preserve the full registry while partitioning only release execution.

## Source Nodes

- process_crash.rs
- production_restore_conformance.rs
- restore_maintenance_api.rs
- maintenance.rs