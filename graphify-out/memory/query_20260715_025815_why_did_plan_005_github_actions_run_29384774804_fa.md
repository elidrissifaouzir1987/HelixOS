---
type: "ci-diagnosis"
date: "2026-07-15T02:58:15.395813+00:00"
question: "Why did PLAN-005 GitHub Actions run 29384774804 fail only on Windows, and what corrected it?"
contributor: "graphify"
outcome: "corrected"
correction: "Pin the frozen PLAN-004 source path to LF at checkout and enforce that pin in CI before raw digest comparison."
source_nodes: ["plan005_fault_registry_and_plan004_anchor_are_frozen", ".gitattributes", "Plan005WorkflowTests"]
---

# Q: Why did PLAN-005 GitHub Actions run 29384774804 fail only on Windows, and what corrected it?

## Answer

The Windows checkout converted kernel/helix-plan-preparation/src/test_fault.rs from LF to CRLF because the file had no explicit end-of-line attribute. The PLAN-005 portability test hashes those raw PLAN-004 source bytes, so Windows produced SHA-256 4398f766afdaa20905e3c96c80b4d6d0301fafa1ce4a4458a175816ea9ec8a5d instead of the frozen LF digest f9d9fd0ff4c3cb1bc7f48f52c0484031c9964c22ff3ce4c29b8f3dc24be07db9. The bounded correction pins that one source path to text eol=lf in .gitattributes, requires the rule in the PLAN-005 workflow path-policy job, and refreshes the workflow digest oracle. The 37 PLAN-005 evidence tests, the exact Rust portability test, git attribute inspection, and diff policy all pass; no protected user Rust file or physical M4 evidence changed.

## Outcome

- Signal: corrected
- Correction: Pin the frozen PLAN-004 source path to LF at checkout and enforce that pin in CI before raw digest comparison.

## Source Nodes

- plan005_fault_registry_and_plan004_anchor_are_frozen
- .gitattributes
- Plan005WorkflowTests