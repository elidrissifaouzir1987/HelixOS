---
type: "implementation"
date: "2026-07-11T08:27:23.915102+00:00"
question: "What did Feature 004 T037 establish for the SQLite PreparationStoreV1 adapter?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["SqliteCoordinatorStoreV1", "PreparationStoreV1", "commit_preparing_transaction_v1", "readback_with_live_snapshot_v1", "CoordinatorUncertainCommitCustodyV1"]
---

# Q: What did Feature 004 T037 establish for the SQLite PreparationStoreV1 adapter?

## Answer

T037 wires SqliteCoordinatorStoreV1 to the portable PreparationStoreV1 boundary using the T033 read-only preflight, the T034 permit-held SQLite commit primitive, and the T035 exact readback classifier. Each operation holds provisioner-attested root and database-file binding custody; uncertain commit stores only exact attempt-keyed custody in a one-shot Mutex while T036 retains and resolves COMMIT_IN_FLIGHT. Fresh readback uses BEGIN IMMEDIATE and runs schema::verify_full in that same snapshot before matching exact event, transition, generations, comparison/replay, budget scope, and recovery bindings. Material bindings come from the exact receipt; irreversible L2 bindings are domain-separated derivations over authenticated facts and fabricate no material. All four transactional budget classes remain distinct, pre-permit deadline is distinct from writer busy, and fail-before-dispatch remains closed Unavailable for T047. Package tests passed with 82 tests, preparation integration passed 15 tests, and default/fault-feature strict Clippy passed.

## Outcome

- Signal: useful

## Source Nodes

- SqliteCoordinatorStoreV1
- PreparationStoreV1
- commit_preparing_transaction_v1
- readback_with_live_snapshot_v1
- CoordinatorUncertainCommitCustodyV1