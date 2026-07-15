---
type: "implementation"
date: "2026-07-13T20:32:43.565020+00:00"
question: "How must the T080 SQLite no-effect corpus compose migration and automatic readback?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["complete_quiescent_backup_and_migrate_dispatch_v2", "run_automatic_readback_once_v1", "CoordinatorAutomaticReadbackPermitV1", "run_t080_production_corpus_for_test_v1"]
---

# Q: How must the T080 SQLite no-effect corpus compose migration and automatic readback?

## Answer

Use the complete quiescent PAUSE/provider/BEGIN IMMEDIATE backup-and-migrate path on the same prepared coordinator root; require committed reopened migration readback. For POSSIBLE_HANDOFF, persist a readback claim, consume its non-clonable permit with run_automatic_readback_once_v1, prove permit reuse is AlreadyClassified, and require a resumed claim after reopen. Lost ACK recovers the exact retained receipt without re-consume. Absence uses exactly four observations at offsets 0/25/100/275 and derives exhaustion evidence from that transcript. Final evidence is measured from read-only SQLite projections and reports zero replacement grants, transport redelivery, and execution-authority objects.

## Outcome

- Signal: useful

## Source Nodes

- complete_quiescent_backup_and_migrate_dispatch_v2
- run_automatic_readback_once_v1
- CoordinatorAutomaticReadbackPermitV1
- run_t080_production_corpus_for_test_v1