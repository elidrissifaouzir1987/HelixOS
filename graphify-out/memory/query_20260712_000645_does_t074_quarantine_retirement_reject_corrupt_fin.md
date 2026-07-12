---
type: "test-outcome"
date: "2026-07-12T00:06:45.260111+00:00"
question: "Does T074 quarantine/retirement reject corrupt final provider tombstones on both terminal paths?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["t074_quarantine.rs", "quarantine.rs", "retirement.rs"]
---

# Q: Does T074 quarantine/retirement reject corrupt final provider tombstones on both terminal paths?

## Answer

Yes. The bounded adversarial test reaches the real orphan-retired and operation-retired hooks, confirms their clean reopen tokens, corrupts the sole retirement tombstone, and requires reopen refusal. The full process_crash binary passed 77 tests with 5 private children ignored.

## Outcome

- Signal: useful

## Source Nodes

- t074_quarantine.rs
- quarantine.rs
- retirement.rs