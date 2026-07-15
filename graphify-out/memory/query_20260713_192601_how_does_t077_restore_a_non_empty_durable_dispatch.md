---
type: "implementation-result"
date: "2026-07-13T19:26:01.644921+00:00"
question: "How does T077 restore a non-empty durable dispatch backup without reviving prior authority?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does T077 restore a non-empty durable dispatch backup without reviving prior authority?

## Answer

The coordinator verifies the signed T076 package, requires fresh clean coordinator and adapter roots plus persisted PAUSE/rotated authority, restores both stores only to RESTORE_PENDING, validates retained coordinator grants append-only and expired, and requires persisted adapter reconciliation grant IDs/digests to cover every risky coordinator grant. The production conformance fixture receives one canonical adapter grant at supervisor epoch 15, reopens the attested store, backs it up as one orphan adapter grant, restores it with exactly one persisted reconciliation quarantine, and proves an exact idempotent retry with zero automatic redelivery. Checks, focused tests, feature tests, and strict clippy passed on 2026-07-13.

## Outcome

- Signal: useful