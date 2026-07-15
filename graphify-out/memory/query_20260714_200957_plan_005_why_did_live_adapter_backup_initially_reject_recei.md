---
type: "query"
feature: "PLAN-005"
date: "2026-07-14T20:09:57.609705+00:00"
question: "Why did live adapter backup initially reject received and consumed stores?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat the open-time summary as identity context, not as the current mutable generation snapshot."
---

# Q: Why did live adapter backup initially reject received and consumed stores?

## Answer

OpenedAdapterInboxStoreV1 captures a summary only at open, so comparing a later verified live-store summary to that stale snapshot rejected legitimate receive or consume mutations as SOURCE_CHANGED. Backup now verifies the current ACTIVE summary and paused supervisor epoch under the store mutex, captures the inventory and backup, then repeats full summary and inventory verification before publication.

## Outcome

- Signal: corrected
- Correction: Treat the open-time summary as identity context, not as the current mutable generation snapshot.
