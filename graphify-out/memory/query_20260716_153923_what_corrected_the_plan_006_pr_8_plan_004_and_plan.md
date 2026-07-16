---
type: "query"
date: "2026-07-16T15:39:23.608668+00:00"
question: "What corrected the PLAN-006 PR 8 PLAN-004 and PLAN-005 policy failures?"
contributor: "graphify"
outcome: "corrected"
correction: "When a downstream plan grows the workspace, update semantic downstream/removal classifications and compare frozen closures after substituting the frozen lock binding; never repin a historical release oracle merely because unreachable local packages were added."
---

# Q: What corrected the PLAN-006 PR 8 PLAN-004 and PLAN-005 policy failures?

## Answer

PLAN-006 added four workspace crates, seven prior-plan policy-test edits, new fixture/crate/Graphify prefixes and a local-only Cargo.lock extension. PLAN-004 still expected only the PLAN-005 downstream packages, and PLAN-005 had not classified the new downstream removal surface or separated its frozen production-closure digest from the current full-lock hash. The correction extends only those downstream guards, preserves the frozen PLAN-005 c5b84e production oracle, and restores all eleven existing integration edits during PLAN-006 removal.

## Outcome

- Signal: corrected
- Correction: When a downstream plan grows the workspace, update semantic downstream/removal classifications and compare frozen closures after substituting the frozen lock binding; never repin a historical release oracle merely because unreachable local packages were added.
