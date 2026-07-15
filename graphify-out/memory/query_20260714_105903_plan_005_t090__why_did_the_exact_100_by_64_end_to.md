---
type: "implementation-result"
date: "2026-07-14T10:59:03.846338+00:00"
question: "PLAN-005 T090: why did the exact 100-by-64 end-to-end gate report ROOT_BUSY?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not weaken production locking or deadlines; isolate strict-open setup from the synchronized operation wave and retain a real last-close restart checkpoint."
source_nodes: ["dispatch_end_to_end_contention.rs", "CoordinatorDescriptorV1", "PreparedCoordinatorRootV1"]
---

# Q: PLAN-005 T090: why did the exact 100-by-64 end-to-end gate report ROOT_BUSY?

## Answer

The production root lease failed closed correctly. The test released 64 workers into strict V2 open and full verification after closing the WAL anchors, so setup lease contention consumed the synthetic acquisition window before the dispatch contention under test. The corrected harness pre-opens one independent coordinator and adapter handle per worker sequentially, retains idle anchors through the wave, and forces the genuine last close only before restart verification. The exact gate then passed with one dispatch and one consumption per round.

## Outcome

- Signal: corrected
- Correction: Do not weaken production locking or deadlines; isolate strict-open setup from the synchronized operation wave and retain a real last-close restart checkpoint.

## Source Nodes

- dispatch_end_to_end_contention.rs
- CoordinatorDescriptorV1
- PreparedCoordinatorRootV1