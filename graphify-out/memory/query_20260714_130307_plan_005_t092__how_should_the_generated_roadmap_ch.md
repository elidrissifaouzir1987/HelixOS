---
type: "query"
date: "2026-07-14T13:03:07.806243+00:00"
question: "PLAN-005 T092: how should the generated roadmap choose focus after SpecKit Converge appends build gaps after existing release tasks?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["update_roadmap.py", "Tasks: Durable One-Shot Dispatch", "HelixOS — Roadmap & Specs v5.0.0"]
---

# Q: PLAN-005 T092: how should the generated roadmap choose focus after SpecKit Converge appends build gaps after existing release tasks?

## Answer

SpecKit Converge is append-only, so newly discovered build gaps can have later IDs than Graphify or release-closure tasks. The roadmap generator now prioritizes the first open unblocked implementation task whose phase title is Convergence within the active feature, then falls back to the prior implementation/decision order. This keeps generated data authoritative without hand-editing it and selects T095 before T093/T094 while T095-T097 remain open.

## Outcome

- Signal: useful

## Source Nodes

- update_roadmap.py
- Tasks: Durable One-Shot Dispatch
- HelixOS — Roadmap & Specs v5.0.0