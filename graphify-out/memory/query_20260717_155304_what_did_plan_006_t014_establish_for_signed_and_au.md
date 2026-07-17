---
type: "query"
date: "2026-07-17T15:53:04.157700+00:00"
question: "What did PLAN-006 T014 establish for signed and authentic task-authority markers?"
contributor: "graphify"
outcome: "useful"
---

# Q: What did PLAN-006 T014 establish for signed and authentic task-authority markers?

## Answer

T014 exposes exactly six opaque marker types for HumanRequestGrantV1, TaskLeaseV1, and ApprovalDecisionV1. Every marker has a private unit field, no caller-visible constructor, no Default/Clone/Copy/Serde conversion, and a manual payload-free Debug implementation. Authentic markers remain linear and caller-nonconstructible. Evidence: 50/50 package tests, strict Clippy, workspace all-target check, and 31/31 prior-plan contract and portability regressions pass.

## Outcome

- Signal: useful