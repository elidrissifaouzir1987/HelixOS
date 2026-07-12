---
type: "implementation"
date: "2026-07-11T10:53:53.844687+00:00"
question: "What did PLAN-004 T045 and the transactional conflict portion of T046 implement?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["commit_preparing_transaction_v1", "classify_preflight_operation_v1", "classify_preflight_budget_v1", "checked_budget_reservation_v1"]
---

# Q: What did PLAN-004 T045 and the transactional conflict portion of T046 implement?

## Answer

The real coordinator preflight now proves operation identity before entering the budget domain, preserving row-30 budget-authority classification. The production prepare path acquires BEGIN IMMEDIATE before full-store verification, repeats full verification after staging and final comparison digest, classifies exact prior occupants as AlreadyPrepared, incompatible operation identity as OperationConflict, reservation reuse as BudgetBindingConflict, and leaves residual post-serialization uniqueness collisions as generic Conflict. Four-dimensional scope arithmetic delegates to the T044 checked aggregate helper before capacity classification, and the closed outcomes map through the portable coordinator. Evidence: coordinator SQLite lib tests 41/41, plan-preparation lib tests 12/12, deadline integration 16/16 plus one ignored. Preparation/contention integration remained blocked until the parallel immutable-digest finalizer was wired into prepare.rs; no digest projection was invented in this work.

## Outcome

- Signal: useful

## Source Nodes

- commit_preparing_transaction_v1
- classify_preflight_operation_v1
- classify_preflight_budget_v1
- checked_budget_reservation_v1