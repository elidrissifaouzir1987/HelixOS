---
type: "implementation"
date: "2026-07-17T17:48:30.371018+00:00"
question: "What did PLAN-006 T015 establish for durable task-authority idempotency and uncertainty?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["AuthorityOperationKindV1", "AuthorityIdempotencyPreimageV1", "AuthorityAttemptBindingV1", "AuthorityUncertainReadbackV1", "AuthorityAtomicStoreV1"]
---

# Q: What did PLAN-006 T015 establish for durable task-authority idempotency and uncertainty?

## Answer

T015 defines the exact nine schema-aligned operation domains, typed canonical stable preimages that exclude candidate-generated values, typed immutable attempt/namespace/input/outcome bindings, six mutation and four readback classifications, and a core-owned non-cloneable consuming uncertainty token. Sixteen unit tests plus a compile-fail non-Clone doctest, strict Clippy, feature checks, prior portability tests, and the locked workspace check passed.

## Outcome

- Signal: useful

## Source Nodes

- AuthorityOperationKindV1
- AuthorityIdempotencyPreimageV1
- AuthorityAttemptBindingV1
- AuthorityUncertainReadbackV1
- AuthorityAtomicStoreV1