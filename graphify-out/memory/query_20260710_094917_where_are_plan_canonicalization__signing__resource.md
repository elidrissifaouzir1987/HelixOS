---
type: "query"
date: "2026-07-10T09:49:17.449900+00:00"
question: "Where are plan canonicalization, signing, resource paths, policy, audit, and persistence implemented, and what should the first portable contract slice isolate?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["Plan", "ScopeLease", "Kernel", "AppendOnlyStore"]
---

# Q: Where are plan canonicalization, signing, resource paths, policy, audit, and persistence implemented, and what should the first portable contract slice isolate?

## Answer

Expanded from the graph vocabulary: plan, canonical, envelope, signature, signed, hash, scope, lease, path, persist, policy, audit. The graph shows Plan and canonical_bytes in kernel/helixos-kernel/src/plan.rs, ScopeLease and PathBuf-based authorization in scope.rs, Kernel plan/persist_consumed state in pipeline.rs, policy in policy.rs, and append-only audit in audit.rs. The first bounded slice should therefore add an independent portable helix-contracts crate for PlanEnvelope v1, resource references, canonical encoding, hashing, and signatures without replacing the legacy pipeline yet.

## Outcome

- Signal: useful

## Source Nodes

- Plan
- ScopeLease
- Kernel
- AppendOnlyStore