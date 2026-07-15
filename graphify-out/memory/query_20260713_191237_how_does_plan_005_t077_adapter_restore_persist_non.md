---
type: "implementation"
date: "2026-07-13T19:12:37.241189+00:00"
question: "How does PLAN-005 T077 adapter restore persist non-delivery reconciliation evidence for non-empty sources?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["transition_imported_backup_to_restore_pending_v1", "verify_restore_pending_v1", "commit_adapter_dispatch_restore_to_pending_v1"]
---

# Q: How does PLAN-005 T077 adapter restore persist non-delivery reconciliation evidence for non-empty sources?

## Answer

The adapter derives one deterministic inbox_quarantines proof for every unchanged source grant in RECEIVED, CONSUMED, or QUARANTINED. In one IMMEDIATE transaction it inserts restore-only proofs at generations above the source store high-water, then rotates metadata to RESTORE_PENDING at N+1. Proof evidence binds the restore index, new root and epoch authority, PAUSE evidence, source state, and grant_id. Strict readback rejects missing, substituted, extra, or resolved proofs; source inventory is reconstructed below the source quarantine high-water while restored inventory includes only the exact additions. Counts, a canonical sorted grant-set digest, and private sorted grant IDs come from persisted readback rows. A production receive API integration test verifies a non-empty source and idempotent retry. Default/all-feature tests, checks, and Clippy -D warnings passed; frozen manifest and schema hashes remained unchanged.

## Outcome

- Signal: useful

## Source Nodes

- transition_imported_backup_to_restore_pending_v1
- verify_restore_pending_v1
- commit_adapter_dispatch_restore_to_pending_v1