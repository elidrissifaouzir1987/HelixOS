---
type: "architecture"
date: "2026-07-10T13:03:50.075240+00:00"
question: "What replay uniqueness namespace must survive signing-key rotation?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not key nonce uniqueness by signing key and do not rely on a prior unused observation; atomically compare and insert both stable indexes."
source_nodes: ["ReplayBindingV1", "DeterministicReplayClaimant", "ReplayAlreadyClaimed", "ReplayBindingConflict"]
---

# Q: What replay uniqueness namespace must survive signing-key rotation?

## Answer

The stable v1 uniqueness key is (instance_epoch, nonce) in the issuer namespace, with a separate operation index. key_id and the exact verified public-key fingerprint are compared binding evidence, not uniqueness-key components. Rotation therefore cannot reopen a consumed nonce; exact repeats deny as already claimed and any changed binding denies as conflict.

## Outcome

- Signal: corrected
- Correction: Do not key nonce uniqueness by signing key and do not rely on a prior unused observation; atomically compare and insert both stable indexes.

## Source Nodes

- ReplayBindingV1
- DeterministicReplayClaimant
- ReplayAlreadyClaimed
- ReplayBindingConflict