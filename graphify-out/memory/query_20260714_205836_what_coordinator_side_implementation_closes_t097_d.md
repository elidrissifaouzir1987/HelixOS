---
type: "implementation"
date: "2026-07-14T20:58:36.749661+00:00"
question: "What coordinator-side implementation closes T097 dispatch-history corruption handling?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["dispatch_quarantine", "dispatch_schema"]
---

# Q: What coordinator-side implementation closes T097 dispatch-history corruption handling?

## Answer

The coordinator SQLite crate now classifies eleven filesystem-derived corruption families from independent coordinator and adapter histories, retains idempotent redacted custody as INVARIANT_CONFLICT or STORE_UNHEALTHY, and keeps V2 admission permanently fenced even after a custody tombstone transition. Five legitimate T096 lifecycle shapes remain clean. Evidence: dispatch_corruption integration tests pass 5/5, the eleven-class exact matrix passes, coordinator quarantine units pass 5/5, and the permanent-fence unit passes 1/1.

## Outcome

- Signal: useful

## Source Nodes

- dispatch_quarantine
- dispatch_schema