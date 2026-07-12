---
type: "query"
date: "2026-07-11T23:49:23.392810+00:00"
question: "How should T074 recovery and quarantine process workflows be routed without exposing private modules to every integration target?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["process_crash.rs", "process_probe.rs"]
---

# Q: How should T074 recovery and quarantine process workflows be routed without exposing private modules to every integration target?

## Answer

Keep the reusable compiled preparation child in common/process_probe.rs, exposing only its two child entry functions. Route recovery and quarantine exclusively from process_crash.rs: validate the child protocol, prepare the module fixture before READY, invoke the selected module after GO with an Arc process barrier, use the module-specific reopen classifier, and delegate every other boundary to the common child. This supports 102 boundaries and 146 expanded cases, preserves 21 explicit transaction/readback/failure gaps, passes the all-targets feature check, and advances the release matrix through recovery to the expected positive_coordinator_commit_permit_resolved_aborted boundary.

## Outcome

- Signal: useful

## Source Nodes

- process_crash.rs
- process_probe.rs