---
type: "implementation"
date: "2026-07-14T17:54:39.149053+00:00"
question: "PLAN-005 T095: what production changes and validation define the fourth physical remediation candidate?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["receive_grant_v1", "commit_dispatch_transaction_v1", "commit_execution_receipt_v1"]
---

# Q: PLAN-005 T095: what production changes and validation define the fourth physical remediation candidate?

## Answer

The fourth candidate removes one redundant current-grant cryptographic verification in adapter receive while preserving a closed historical-only fallback; removes four repeated PRAGMA reads after the complete V2 snapshot proof on the same private BEGIN IMMEDIATE connection; removes a second nine-table receipt-context reload before private staging in the same writer snapshot; and reuses the already-read reconciliation high-water instead of a second metadata SELECT. Full pre/post V2 graph verification, WAL/FULL, exact CAS writes, foreign-key checks, current/historical authority separation, epoch observations, root/file custody, and uncertain commit custody remain unchanged. Independent review returned GO. Validation passed: adapter full suite, coordinator lib 149, targeted dispatch/receipt/corruption/schema integrations, benchmark unit tests 6, end-to-end 56 passed/0 failed/3 ignored, fault matrix 54/0/6, and workspace all-target/all-feature Clippy with warnings denied.

## Outcome

- Signal: useful

## Source Nodes

- receive_grant_v1
- commit_dispatch_transaction_v1
- commit_execution_receipt_v1