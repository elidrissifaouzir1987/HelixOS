---
type: "query"
date: "2026-07-14T13:07:47.208394+00:00"
question: "PLAN-005 T092: how can the roadmap page show appended Convergence work first without changing the protected roadmap generator?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["index.html", "update_roadmap.py", "plan005_removal_drill.py", "Tasks: Durable One-Shot Dispatch"]
---

# Q: PLAN-005 T092: how can the roadmap page show appended Convergence work first without changing the protected roadmap generator?

## Answer

Keep tools/update_roadmap.py byte-identical to the protected baseline and leave roadmap-data.js fully generated. In the already removal-allowlisted docs/roadmap/index.html presentation layer, derive an effective focus from the first open unblocked implementation task in the active plan whose phase is Convergence, falling back to generated currentFocus. Hero, focus card, task label and task ordering share that helper. The UI therefore shows T095 while T095-T097 are open, without widening the PLAN-005 removal manifest. JavaScript syntax, roadmap freshness, removal source-delta classification and privacy checks passed.

## Outcome

- Signal: useful

## Source Nodes

- index.html
- update_roadmap.py
- plan005_removal_drill.py
- Tasks: Durable One-Shot Dispatch