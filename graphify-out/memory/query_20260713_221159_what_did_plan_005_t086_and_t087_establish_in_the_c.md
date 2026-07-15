---
type: "implementation"
date: "2026-07-13T22:11:59.371188+00:00"
question: "What did PLAN-005 T086 and T087 establish in the conformance catalog and roadmap?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["conformance/catalog.yaml", "specs/005-durable-dispatch/tasks.md", "docs/roadmap/roadmap-data.js"]
---

# Q: What did PLAN-005 T086 and T087 establish in the conformance catalog and roadmap?

## Answer

T086 now maps exactly GRANT-001, DUR-001, DUR-002, OPS-002, OPS-003, SUPPLY-001, and PERF-002 to named owners and the eight internal PLAN-005 evidence gates. It binds all five durable-dispatch corpus artifacts and their reviewed digests, records the complete measurable thresholds, separates immutable hosted CI from physical M4, power-loss, production, restore, and Tier 1 external gates, and retains aggregate claim_status pending-evidence. T087 regenerated roadmap-data.js only through tools/update_roadmap.py and verified PLAN-005 at 86 of 94 tasks, phase 7 at 5 of 12, eight remaining, with pending-evidence unchanged.

## Outcome

- Signal: useful

## Source Nodes

- conformance/catalog.yaml
- specs/005-durable-dispatch/tasks.md
- docs/roadmap/roadmap-data.js