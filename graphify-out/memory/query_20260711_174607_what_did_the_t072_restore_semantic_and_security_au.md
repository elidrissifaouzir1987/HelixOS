---
type: "review"
date: "2026-07-11T17:46:07.773400+00:00"
question: "What did the T072 restore semantic and security audit require before completion?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["restore_preparation_to_pending_v1", "RestorePackageCustodyV1", "CoordinatorRestoreRootCustodyV1", "RecoveryRestoreProviderV1", "RestoreQuarantineEvidenceV1", "VerifiedPreparationRestoreV1"]
---

# Q: What did the T072 restore semantic and security audit require before completion?

## Answer

T072 must bind one durable begin-or-resume attempt to the authenticated package and both provisioner-owned destination reservations, retain stable restore and root identities, classify interrupted coordinator and recovery phases without overwriting an already RESTORE_PENDING database, persist exact root-bound quarantine before releasing custody, and prove process-reopen inventory without in-memory state. Package acceptance must quarantine invalid provenance and keep the SQLite source tied to captured bytes; raw destination SHA-256 equality is not a valid oracle because SQLite online backup rewrites volatile header counters even from a DELETE-normalized source. The restore identity domain and preimage must match the recovery-root schema exactly. Non-activation, WAL/FULL establishment, exact provider reconciliation, dual pending agreement, redaction, and backup DELETE normalization were otherwise fail-closed.

## Outcome

- Signal: useful

## Source Nodes

- restore_preparation_to_pending_v1
- RestorePackageCustodyV1
- CoordinatorRestoreRootCustodyV1
- RecoveryRestoreProviderV1
- RestoreQuarantineEvidenceV1
- VerifiedPreparationRestoreV1