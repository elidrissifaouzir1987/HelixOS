---
type: "implementation_result"
date: "2026-07-17T19:39:39.056351+00:00"
question: "What did PLAN-006 T016 establish for trusted control and projection custody?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["AuthorityDeadlineV1", "AuthorityProjectionGuardV1", "CurrentAuthorityProjectionV1", "AuthorityDownstreamCommitPermitV1"]
---

# Q: What did PLAN-006 T016 establish for trusted control and projection custody?

## Answer

T016 establishes an injected coherent UTC/monotonic clock with immutable earliest absolute deadlines and exact boot, clock-generation, and instance bindings; fixed queue capacities of 1024 ordinary and 32 reserved control; core-sealed guard and projection providers so external backends cannot fabricate Current; one physical non-cloneable guard that stores one exact request and owns one linear deadline across Lease, Authorization, FinalCommit, one-shot downstream classification, explicit later-permit abandonment, and HLXA release; positive projection views borrow real verified custody and cannot be cloned, serialized, constructed, or escaped.

## Outcome

- Signal: useful

## Source Nodes

- AuthorityDeadlineV1
- AuthorityProjectionGuardV1
- CurrentAuthorityProjectionV1
- AuthorityDownstreamCommitPermitV1