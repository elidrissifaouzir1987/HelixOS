---
type: "implementation"
date: "2026-07-13T15:13:23.595444+00:00"
question: "What did PLAN-005 T067 establish about durable readback exhaustion, late receipts, and definite refusal?"
contributor: "graphify"
outcome: "corrected"
correction: "The earlier design coupled readback claim with OUTCOME_UNKNOWN and used per-axis generation increments. That was incorrect: claim and exhaustion are separate durable steps, and mutated axes must be allocated from the global store high-water so full V2 verification remains exact."
---

# Q: What did PLAN-005 T067 establish about durable readback exhaustion, late receipts, and definite refusal?

## Answer

T067 now keeps the durable readback claim distinct from exhaustion: a fresh claim leaves the record DISPATCHING and moves only handoff custody to UNKNOWN; exact exhaustion later commits OUTCOME_UNKNOWN and explicit reconciliation commits RECONCILIATION_REQUIRED. Late CONSUMED receipts remain append-only reconciliation evidence and never restore EXECUTING. A signed post-RECEIVED definite refusal with exact root, epoch, attempt, handoff generation, deadline and no-consumption tombstone atomically appends overlay/base FAILED, both event chains, a quiesced outbox and exactly one reservation release. Every mutated transaction allocates from the global store high-water, revalidates the full staged snapshot before COMMIT, and accepts retries only when persisted exhaustion evidence, trace and latency are exact. Real E2E tests cover consumed receipt, late consumed custody, and ADAPTER_PAUSED refusal with PriorExact after reopen in default and fault-injection builds; coordinator suites excluding the previously completed long SC-001 matrices and strict clippy passed.

## Outcome

- Signal: corrected
- Correction: The earlier design coupled readback claim with OUTCOME_UNKNOWN and used per-axis generation increments. That was incorrect: claim and exhaustion are separate durable steps, and mutated axes must be allocated from the global store high-water so full V2 verification remains exact.