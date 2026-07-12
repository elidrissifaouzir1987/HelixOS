---
type: "audit"
date: "2026-07-11T22:08:17.048473+00:00"
question: "Does Feature 004 T075 currently expose a callable bounded restore-maintenance API without activation authority?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["maintenance.rs", "lib.rs", "VerifiedPreparationRestoreV1", "PausedRotatedRestoreAuthorityV1"]
---

# Q: Does Feature 004 T075 currently expose a callable bounded restore-maintenance API without activation authority?

## Answer

RED: lib.rs exports only redacted errors, limits, and evidence. The only production old-authority operation, reconcile_restored_old_authority_v1, remains crate-private, as do both restore producers; therefore external code cannot obtain or invoke the exported evidence path. Redaction, typed PAUSE-to-T073 rotation linkage, RESTORE_PENDING CAS checks, and absence of ACTIVE/dispatch transitions pass. A safe fix is an opaque non-Clone PendingRestoreMaintenanceV1 returned by the trusted restore host path, with a public bounded reconcile method backed by a private closure/core; low-level paths, digests, PAUSE, custody, and rotation remain private.

## Outcome

- Signal: useful

## Source Nodes

- maintenance.rs
- lib.rs
- VerifiedPreparationRestoreV1
- PausedRotatedRestoreAuthorityV1