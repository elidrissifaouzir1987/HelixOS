---
type: "query"
date: "2026-07-13T15:28:56.001450+00:00"
question: "What did PLAN-005 T071 establish before backup manifest production code exists?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["dispatch-backup-manifest-v1.schema.json", "dispatch_restore.rs", "backup_restore.rs"]
---

# Q: What did PLAN-005 T071 establish before backup manifest production code exists?

## Answer

T071 added compile-safe RED integration tests derived from the frozen dispatch-backup-manifest-v1 schema. They pin the exact coordinator V2 and adapter inbox V1 package constants; complete generation, count, and inventory field sets; coordinator then adapter then signed-index-last order; three distinct verifier purposes and signature domains; RFC 8785/SHA-256/Ed25519 signature profile; closed-member secret/private-key exclusion; and runtime gates for the future coordinator dispatch_manifest.rs and adapter manifest.rs canonical codecs. Targeted Cargo runs compile successfully, pass every frozen-schema assertion, and fail only at the two missing T075 production modules.

## Outcome

- Signal: useful

## Source Nodes

- dispatch-backup-manifest-v1.schema.json
- dispatch_restore.rs
- backup_restore.rs