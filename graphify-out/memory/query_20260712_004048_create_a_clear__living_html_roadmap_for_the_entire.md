---
type: "query"
date: "2026-07-12T00:40:48.729610+00:00"
question: "Create a clear, living HTML roadmap for the entire HelixOS project"
contributor: "graphify"
outcome: "useful"
source_nodes: ["ROADMAP-SPECS.md", "Tasks: Durable Replay Claim Store", "Phase 7: Polish and Cross-Cutting Release Evidence"]
---

# Q: Create a clear, living HTML roadmap for the entire HelixOS project

## Answer

Expanded from the project graph vocabulary: catalog, constitution, evidence, feature, pending, phase, plan, progress, project, release, roadmap, status, tasks. Created docs/roadmap/index.html with separate strategic R0-R8, tracked PLAN task progress, conformance evidence, current focus, blockers, and remaining work. tools/update_roadmap.py deterministically regenerates roadmap-data.js from ROADMAP-SPECS.md, specs task files, and conformance/catalog.yaml; AGENTS.md and a pinned CI freshness workflow require updates at each stage. Browser validation covered desktop, 375-pixel mobile layout, and both filters.

## Outcome

- Signal: useful

## Source Nodes

- ROADMAP-SPECS.md
- Tasks: Durable Replay Claim Store
- Phase 7: Polish and Cross-Cutting Release Evidence