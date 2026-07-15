---
type: "plan-005-t095-closure"
date: "2026-07-14T18:49:44.489529+00:00"
question: "What closed PLAN-005 T095 after the final physical remediation?"
contributor: "graphify"
outcome: "useful"
---

# Q: What closed PLAN-005 T095 after the final physical remediation?

## Answer

T095 passed on the fourth complete 500-warmup/10,000-sample physical Mac mini M4 run: p95 49.416541 ms and p99 51.917875 ms. The final raw artifact SHA-256 is c37c2d3dde82bcb7da86b0400e4abccf64a0358a4a056f0aad8a8e9396af343f. A refreshed fail-closed removal manifest protects 22 explicit baseline paths with SHA-256 c45caacf0184c9e0150122b89887037b01b92d9bf3163d583399d9b911d13a7a; its fresh diagnostic drill protected 495 baseline leaves, removed 149 added paths, retained 35 audit paths, and passed five offline semantic commands. A new diagnostic supply-chain bundle independently verified 80 production packages, 137 dependency edges and 10 SPDX texts while remaining pending-evidence and non-immutable. Roadmap is 93/97 for PLAN-005 and 314/318 globally.

## Outcome

- Signal: useful