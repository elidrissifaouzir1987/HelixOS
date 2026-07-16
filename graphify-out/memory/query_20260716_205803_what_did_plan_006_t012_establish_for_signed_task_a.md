---
type: "query"
date: "2026-07-16T20:58:03.408897+00:00"
question: "What did PLAN-006 T012 establish for signed task-authority cryptography?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["CanonicalEd25519SignatureV1", "VerifiedKeyEvidenceV1", "HumanRequestGrantKeyResolver", "TaskLeaseKeyResolver", "ApprovalDecisionKeyResolver", "decode_signature()", "verify()"]
---

# Q: What did PLAN-006 T012 establish for signed task-authority cryptography?

## Answer

T012 added a canonical base64url-no-pad signature token that is constructible only after exact 86-character decode and re-encode validation; three purpose-specific signer, resolver, and verification-key APIs for human grants, task leases, and approval decisions; strict Ed25519 verification over caller-supplied domain-separated protected bytes; and opaque immutable evidence whose SHA-256 fingerprint is derived from the exact resolved 32-byte public key only after successful verification while preserving Current or Historical status. A temporary T013/T014 compile harness passed 15 unit tests and Clippy with warnings denied; permanent source tests remain intentionally RED only for error.rs, validation.rs, authentic markers, and lib.rs wiring.

## Outcome

- Signal: useful

## Source Nodes

- CanonicalEd25519SignatureV1
- VerifiedKeyEvidenceV1
- HumanRequestGrantKeyResolver
- TaskLeaseKeyResolver
- ApprovalDecisionKeyResolver
- decode_signature()
- verify()