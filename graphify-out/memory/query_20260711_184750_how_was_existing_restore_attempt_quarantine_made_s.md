---
type: "implementation"
date: "2026-07-11T18:47:50.421380+00:00"
question: "How was existing restore-attempt quarantine made stable against coordinator/recovery root swaps and generation changes?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["quarantine_existing_restore_attempt_v1", "CoordinatorRestoreInspectionCustodyV1", "RecoveryRestoreInspectionCustodyV1", "PausedRotatedRestoreAuthorityV1"]
---

# Q: How was existing restore-attempt quarantine made stable against coordinator/recovery root swaps and generation changes?

## Answer

quarantine_existing_restore_attempt_v1 now verifies the PAUSE ticket's two provisioner reservation bindings, reacquires read-only coordinator marker/database custody keyed by the ticket root identity, acquires provider inspection custody for the recovery root, captures started/generation evidence, and rechecks both root custodies plus PAUSE before and after idempotent quarantine persistence. Noncanonical or wrong-identity markers are never repaired, physical directory/lock substitutions fail closed, and changed recovery generations are refused. Targeted root-safety tests and production restore conformance pass.

## Outcome

- Signal: useful

## Source Nodes

- quarantine_existing_restore_attempt_v1
- CoordinatorRestoreInspectionCustodyV1
- RecoveryRestoreInspectionCustodyV1
- PausedRotatedRestoreAuthorityV1