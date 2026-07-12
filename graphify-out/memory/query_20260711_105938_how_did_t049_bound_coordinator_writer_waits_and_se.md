---
type: "implementation"
date: "2026-07-11T10:59:38.575589+00:00"
question: "How did T049 bound coordinator writer waits and select private faults?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["FaultSessionV1", "BoundCoordinatorConnectionV1"]
---

# Q: How did T049 bound coordinator writer waits and select private faults?

## Answer

Added caller-owned fault selection sessions with exact nonzero occurrence matching, one-shot effects, stable redacted diagnostics, and no ambient selector. Busy timeouts now use min of live remaining deadline, configured cap, and SQLite limit, fail closed after arming, and are re-armed immediately before commit, readback, and known-failure BEGIN IMMEDIATE. Unit, contention, deadline, rustfmt, and clippy checks passed. Of 85 coordinator boundaries, 27 are currently referenced and 58 future recovery, backup, restore, and retirement boundaries remain unwired.

## Outcome

- Signal: useful

## Source Nodes

- FaultSessionV1
- BoundCoordinatorConnectionV1