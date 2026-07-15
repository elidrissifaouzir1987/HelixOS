---
type: "performance"
date: "2026-07-14T14:04:29.270160+00:00"
question: "Which phase causes the T095 physical M4 p95 regression?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["durable_dispatch_benchmark.rs", "claim_or_resume_readback_sequence_v1", "commit_execution_receipt_v1"]
---

# Q: Which phase causes the T095 physical M4 p95 regression?

## Answer

An exact 500-warmup/10000-sample Mac mini M4 characterization (temporary create-only artifact SHA256 8b5ea043696332bc9adea31f135adccdf21e81562b7833698e16a45084e2d0d3) measured total p50 57.008 ms, p95 62.747 ms, p99 67.255 ms. The acknowledged-handoff-to-readback-claim segment alone measured p50 12.673 ms and p95 13.529 ms. Removing only that nominally unnecessary readback segment sample-by-sample projects p50 44.322 ms, p95 49.221 ms, p99 52.855 ms. Five required WAL/FULL commits remain; ambiguous PossibleHandoff readback remains unchanged.

## Outcome

- Signal: useful

## Source Nodes

- durable_dispatch_benchmark.rs
- claim_or_resume_readback_sequence_v1
- commit_execution_receipt_v1