---
type: "implementation"
date: "2026-07-11T16:37:40.287670+00:00"
question: "How can base quarantine custody be reused safely inside an existing SQLite transaction?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["retain_base_quarantine_v1()", "retain_base_quarantine_in_transaction_v1()", "quarantine.rs"]
---

# Q: How can base quarantine custody be reused safely inside an existing SQLite transaction?

## Answer

Use the crate-private retain_base_quarantine_in_transaction_v1 helper. It validates ordinary ACTIVE lifecycle and input invariants, classifies exact repeats as Existing, advances store/quarantine generations and inserts plus fires the hook only for Inserted, and never commits or rolls back. The legacy wrapper prevalidates, opens IMMEDIATE, commits Inserted, and rolls back Existing to preserve its boundary.

## Outcome

- Signal: useful

## Source Nodes

- retain_base_quarantine_v1()
- retain_base_quarantine_in_transaction_v1()
- quarantine.rs