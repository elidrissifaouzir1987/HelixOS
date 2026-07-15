---
type: "query"
date: "2026-07-14T13:05:08.747324+00:00"
question: "PLAN-005 T092 correction: may the roadmap generator prioritize appended Convergence tasks directly?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not modify the protected baseline roadmap generator inside this convergence task; preserve removal classification and communicate the dependency order explicitly."
source_nodes: ["update_roadmap.py", "plan005_removal_drill.py", "Tasks: Durable One-Shot Dispatch"]
---

# Q: PLAN-005 T092 correction: may the roadmap generator prioritize appended Convergence tasks directly?

## Answer

Corrected result: not within PLAN-005 as attempted. Changing tools/update_roadmap.py modified a protected baseline path outside the PLAN-005 removal restoration allowlist, and test_current_filtered_source_delta_matches_exactly_one_policy_class failed closed. The generator change was reverted byte-for-byte and all 36 PLAN-005 evidence tests passed. The generated roadmap still contains accurate 92/97 and 313/318 counts plus all five open tasks; the operational handoff explicitly orders T095-T097 before T093/T094. Any generic focus-priority change requires a separately scoped baseline/removal update rather than weakening or silently widening PLAN-005 removal policy.

## Outcome

- Signal: corrected
- Correction: Do not modify the protected baseline roadmap generator inside this convergence task; preserve removal classification and communicate the dependency order explicitly.

## Source Nodes

- update_roadmap.py
- plan005_removal_drill.py
- Tasks: Durable One-Shot Dispatch