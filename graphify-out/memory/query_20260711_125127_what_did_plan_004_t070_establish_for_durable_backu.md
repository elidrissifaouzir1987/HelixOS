---
type: "implementation"
date: "2026-07-11T12:51:27.082935+00:00"
question: "What did PLAN-004 T070 establish for durable backup manifests?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["manifest.rs", "PreparationBackupManifestV1", "RecoverySnapshotManifestV1", "BackupProvenanceAttestationV1", "RecoveryRootMetadataV1"]
---

# Q: What did PLAN-004 T070 establish for durable backup manifests?

## Answer

T070 added typed RFC 8785 finalizers for all four closed backup/restore JSON schemas, exact big-endian package-binding preimages, both frozen 207/240-byte KATs, sorted and duplicate-rejecting multi-provider inventory construction, closed custody/state combinations, and authoritative fixed-zero pending-retirement enforcement in manifest.rs. Evidence: 10 manifest unit tests, 7 portability tests, 3 T064 integration cases, and targeted strict Clippy passed. The full backup_restore target had exactly the two expected later-task REDs for T071 backup publication and T072 dual-root restore orchestration.

## Outcome

- Signal: useful

## Source Nodes

- manifest.rs
- PreparationBackupManifestV1
- RecoverySnapshotManifestV1
- BackupProvenanceAttestationV1
- RecoveryRootMetadataV1