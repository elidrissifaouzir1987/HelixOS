---
type: "query"
feature: "PLAN-005"
date: "2026-07-14T20:09:57.558362+00:00"
question: "How is the coordinator restore stamp admitted without weakening overlay immutability?"
contributor: "graphify"
outcome: "useful"
---

# Q: How is the coordinator restore stamp admitted without weakening overlay immutability?

## Answer

The dispatch metadata transition ACTIVE to RESTORE_PENDING occurs first inside one BEGIN IMMEDIATE transaction. The overlay trigger then admits only restored_source_generation NULL to the exact source generation while all twenty other prepared-operation columns remain byte/value identical and the base store is still ACTIVE without restore bindings. Base stamping follows in the same transaction, and any rejection rolls back both metadata and stamp.

## Outcome

- Signal: useful
