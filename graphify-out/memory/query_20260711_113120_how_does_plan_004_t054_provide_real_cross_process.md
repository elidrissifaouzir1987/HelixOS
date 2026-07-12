---
type: "implementation"
date: "2026-07-11T11:31:20.852554+00:00"
question: "How does PLAN-004 T054 provide real cross-process recovery publication and cleanup custody?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["SyntheticManifestLastRecoveryProviderV1", "SyntheticRecoveryNamespaceGuardV1", "mod.rs", "recovery_integration.rs"]
---

# Q: How does PLAN-004 T054 provide real cross-process recovery publication and cleanup custody?

## Answer

The downstream synthetic provider uses one standard-library exclusive file lock per manifest-bound namespace for both publication and cleanup, so separate processes contend and process exit releases custody. It publishes synchronized material through same-volume no-clobber hard-linking, then synchronizes and publishes the immutable manifest last, reopens exact bytes, and returns only conformance evidence. Retirement is idempotent: while holding the cleanup guard it retains the original manifest, removes material, publishes and reopens an immutable retirement tombstone, and returns the same digest on exact repeat. All 13 RECOVERY and 3 provider-retirement section-14 hooks are feature-gated.

## Outcome

- Signal: useful

## Source Nodes

- SyntheticManifestLastRecoveryProviderV1
- SyntheticRecoveryNamespaceGuardV1
- mod.rs
- recovery_integration.rs