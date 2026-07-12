---
type: "query"
date: "2026-07-12T01:04:52.568730+00:00"
question: "Option B T075 Rust API audit"
contributor: "graphify"
outcome: "useful"
source_nodes: ["VerifiedPreparationRestoreV1", "RestoredPreparationMaintenanceEvidenceV1", "RestoreMaintenanceLimitsV1", "maintenance.rs", "lib.rs", "portability.rs"]
---

# Q: Option B T075 Rust API audit

## Answer

Expanded from the audit via graph vocabulary: [authority, backup, evidence, maintenance, paused, portability, public, quarantine, redacted, removal, restore, trust]. The default crate surface re-exports two non-authoritative evidence types plus four inert payload-free error/limit descriptors, but no public producer or restore/reconciliation operation. Every PAUSE, fencing, recovery, trust/revocation, quarantine and no-dispatch authority type and operation remains inside the private maintenance module as pub(crate). The feature-gated hidden T072 entry is synthetic conformance wiring, not a default production authority facade. Under the clarified Option B requirement allowing at most a read-only evidence type surface with no public producer, no production Rust change is required; the targeted restore-maintenance API, portability/removal and redaction tests pass.

## Outcome

- Signal: useful

## Source Nodes

- VerifiedPreparationRestoreV1
- RestoredPreparationMaintenanceEvidenceV1
- RestoreMaintenanceLimitsV1
- maintenance.rs
- lib.rs
- portability.rs