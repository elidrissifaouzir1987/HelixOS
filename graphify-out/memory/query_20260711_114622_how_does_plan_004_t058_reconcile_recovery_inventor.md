---
type: "implementation"
date: "2026-07-11T11:46:22.717165+00:00"
question: "How does PLAN-004 T058 reconcile recovery inventory before backup?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["maintenance.rs", "RecoveryMaintenanceProviderV1"]
---

# Q: How does PLAN-004 T058 reconcile recovery inventory before backup?

## Answer

A private typed provider surface enumerates only published material or retired tombstones while borrowed cleanup custody is live. maintenance.rs compares exact operation provider/material bindings and quarantine manifest custody in a read-only SQLite snapshot, rejects duplicate/missing/extra/substituted entries, ignores resolved non-orphan ambiguity tombstones, counts operation-bound and orphan RETIREMENT_PENDING separately, and returns a typed BackupBlocked outcome if either count is nonzero. Exact reconciliation reaches the closed BackupProviderEnumerationReconciled hook.

## Outcome

- Signal: useful

## Source Nodes

- maintenance.rs
- RecoveryMaintenanceProviderV1