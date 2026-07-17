---
type: "correction"
date: "2026-07-17T20:41:28.661622+00:00"
question: "What corrected the PLAN-006 T023 queue deadline review gap?"
contributor: "graphify"
outcome: "corrected"
correction: "Never retain a pre-wait deadline sample across a blocking queue or completion mutex acquisition; recapture outside custody before each non-blocking acquisition and test the lock-held-through-exclusive-boundary race."
source_nodes: ["queue.rs", "AuthorityDeadlineV1"]
---

# Q: What corrected the PLAN-006 T023 queue deadline review gap?

## Answer

The first queue implementation recaptured deadlines before blocking Mutex::lock calls, so lock wait time could outlive the sample. The corrected implementation recaptures before every non-blocking try_lock, yields without holding custody when contended, fails closed on poison, and proves both admission and completed-follower fast paths with mutex-held-through-expiry tests.

## Outcome

- Signal: corrected
- Correction: Never retain a pre-wait deadline sample across a blocking queue or completion mutex acquisition; recapture outside custody before each non-blocking acquisition and test the lock-held-through-exclusive-boundary race.

## Source Nodes

- queue.rs
- AuthorityDeadlineV1