---
type: "debugging"
date: "2026-07-11T09:04:58.147129+00:00"
question: "Can a new shared-scope reservation finalize only its own joined comparison digest?"
contributor: "graphify"
outcome: "corrected"
correction: "Recompute every affected synthetic comparison digest inside the same canonical transaction after the shared scope delta. Audit the production current-operation-only finalizer before claiming full shared-scope support."
source_nodes: ["finalize_production_comparison_digest_v1", "finalize_all_synthetic_comparison_digests_v1", "verify_comparison_digests"]
---

# Q: Can a new shared-scope reservation finalize only its own joined comparison digest?

## Answer

No. The first T042 run committed the correct four operations but full reopen failed because each joined comparison digest includes the mutable shared scope held totals. Finalizing only the new row leaves prior digests stale.

## Outcome

- Signal: corrected
- Correction: Recompute every affected synthetic comparison digest inside the same canonical transaction after the shared scope delta. Audit the production current-operation-only finalizer before claiming full shared-scope support.

## Source Nodes

- finalize_production_comparison_digest_v1
- finalize_all_synthetic_comparison_digests_v1
- verify_comparison_digests