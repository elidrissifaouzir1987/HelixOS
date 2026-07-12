---
type: "query"
date: "2026-07-12T00:48:23.064618+00:00"
question: "Audit tools/update_roadmap.py focus-selection logic after T074 would close"
contributor: "graphify"
outcome: "useful"
source_nodes: ["update_roadmap.py", "build_data"]
---

# Q: Audit tools/update_roadmap.py focus-selection logic after T074 would close

## Answer

Expanded from original query via graph vocabulary: [roadmap, generator, decision, blocked, implementation, priority, status, task, phase, plan, update, open]. The roadmap generator now deterministically selects the active plan's first unblocked implementation task, otherwise its first open decision, otherwise its first remaining open task. A non-mutating simulation with PLAN-004 T074 closed selected T085 (decision), not blocked T075. Python syntax and roadmap freshness checks passed.

## Outcome

- Signal: useful

## Source Nodes

- update_roadmap.py
- build_data