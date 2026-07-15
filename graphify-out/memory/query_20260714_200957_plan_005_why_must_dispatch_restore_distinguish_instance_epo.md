---
type: "query"
feature: "PLAN-005"
date: "2026-07-14T20:09:57.509851+00:00"
question: "Why must dispatch restore distinguish instance epoch from fencing supervisor epoch?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not compare adapter supervisor_epoch to coordinator instance_epoch or pass one epoch value for both authority domains."
---

# Q: Why must dispatch restore distinguish instance epoch from fencing supervisor epoch?

## Answer

Prepared operation instance_epoch binds coordinator authority, while fencing_epoch is the adapter supervisor epoch. Cross-store backup and restore must compare the adapter supervisor epoch to the paused fencing epoch, rotate instance and supervisor epochs independently by one, and rotate the adapter epoch-observer generation independently.

## Outcome

- Signal: corrected
- Correction: Do not compare adapter supervisor_epoch to coordinator instance_epoch or pass one epoch value for both authority domains.
