---
type: "implementation"
date: "2026-07-11T16:55:42.272960+00:00"
question: "What did the T072 manifest acceptance boundary establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["VerifiedRestorePackageBindingsV1", "verify_restore_package_manifests_v1", "VerifiedRecoveryRootPendingBindingsV1", "manifest.rs"]
---

# Q: What did the T072 manifest acceptance boundary establish?

## Answer

manifest.rs now verifies exact canonical attestation, top-level, and inventory bytes in closed decode then zero-pending cross-validation then pinned non-revoked Ed25519 provenance order. Only afterward it projects redacted non-wire typed restore bindings for digests, identifiers, generations, counts, lifecycle requirements, and canonically ordered provider sets and entries. Exact RESTORE_PENDING recovery-root metadata has a separate typed redacted proof. Fifteen targeted manifest tests pass, including exact acceptance, revoked trust, coherent top-level substitution rejection, typed projection, redaction, and pending-root projection.

## Outcome

- Signal: useful

## Source Nodes

- VerifiedRestorePackageBindingsV1
- verify_restore_package_manifests_v1
- VerifiedRecoveryRootPendingBindingsV1
- manifest.rs