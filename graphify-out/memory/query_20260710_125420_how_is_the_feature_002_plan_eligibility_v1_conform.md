---
type: "implementation"
date: "2026-07-10T12:54:20.014565+00:00"
question: "How is the feature 002 plan-eligibility v1 conformance corpus registered and executed?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["conformance_cases.rs", "conformance.rs", "eligibility_corpus.rs"]
---

# Q: How is the feature 002 plan-eligibility v1 conformance corpus registered and executed?

## Answer

A shared test-support registry deterministically generates 106 sorted public cases: one coherent case, five concrete checked-constructor failures, and all 100 current runtime denial codes. Every runtime code is produced by an exhaustive real context mutation or closed replay claimant scenario; execution asserts the actual first code, outcome, and claimant call probe before emitting the four-field RFC 8785 summary. The targeted conformance test passed 3/3 and strict Clippy passed.

## Outcome

- Signal: useful

## Source Nodes

- conformance_cases.rs
- conformance.rs
- eligibility_corpus.rs