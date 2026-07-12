---
type: "result"
date: "2026-07-12T18:23:29.071266+00:00"
question: "How are PLAN-004 supply-chain and removal shortcuts prevented from inheriting the physical-M4 local commit?"
contributor: "graphify"
outcome: "corrected"
correction: "Bind nested evidence shortcuts to their own exact commit whenever their parent evidence block uses a different source commit."
source_nodes: ["PLAN-004"]
---

# Q: How are PLAN-004 supply-chain and removal shortcuts prevented from inheriting the physical-M4 local commit?

## Answer

The catalog keeps the convenience pointers under evidence.local but now adds explicit supply_chain_commit and removal_commit fields, both bound to immutable evidence commit 69c15001284e613aca534fd8862dd001f9831fdc. The parent local commit remains f7b021d only for local M4 evidence.

## Outcome

- Signal: corrected
- Correction: Bind nested evidence shortcuts to their own exact commit whenever their parent evidence block uses a different source commit.

## Source Nodes

- PLAN-004