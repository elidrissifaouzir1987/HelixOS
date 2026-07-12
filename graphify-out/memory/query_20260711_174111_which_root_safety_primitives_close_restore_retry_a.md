---
type: "implementation"
date: "2026-07-11T17:41:11.417035+00:00"
question: "Which root-safety primitives close restore retry and package path-ABA gaps for T072?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["RestorePackageCustodyV1", "CoordinatorRestoreRootCustodyV1", "ProvisionedRestorePackageV1", "ProvisionedEmptyCoordinatorRootV1", "root_safety.rs"]
---

# Q: Which root-safety primitives close restore retry and package path-ABA gaps for T072?

## Answer

RestorePackageCustodyV1 now binds every file to a retained handle, filesystem identity, exact length, and streaming SHA-256, with positional handle revalidation. copy_member_to_v1 streams a bound member into an empty create-only regular file, syncs and verifies the destination digest, and revalidates custody before return so maintenance can consume a private snapshot instead of a racy package path. CoordinatorRestoreRootCustodyV1 records whether the database binding existed at begin/resume and exposes a read-only revalidating query. Both provisioned package and empty coordinator roots expose domain-separated opaque hashes of their attested filesystem directory identities while Debug remains redacted. Eleven root-safety tests, all 111 library tests, rustfmt, and strict lib clippy pass.

## Outcome

- Signal: useful

## Source Nodes

- RestorePackageCustodyV1
- CoordinatorRestoreRootCustodyV1
- ProvisionedRestorePackageV1
- ProvisionedEmptyCoordinatorRootV1
- root_safety.rs