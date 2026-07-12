---
type: "implementation"
date: "2026-07-11T11:15:43.814528+00:00"
question: "What T051 integration seam freezes PLAN-004 recovery retirement ordering?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["recovery_integration.rs", "quarantine.rs", "maintenance.rs", "retirement.rs"]
---

# Q: What T051 integration seam freezes PLAN-004 recovery retirement ordering?

## Answer

The RED integration contract separates active orphan quarantine, guarded definitive no-reference authorization, coordinator RETIREMENT_PENDING, provider immutable retirement-tombstone publication, and coordinator RETIRED_TOMBSTONE. Operation-bound retirement first requires durable FAILED plus RELEASED budget; true-orphan retirement creates no operation, reservation, transition, or event. Publication and cleanup guards are cross-process mutually exclusive.

## Outcome

- Signal: useful

## Source Nodes

- recovery_integration.rs
- quarantine.rs
- maintenance.rs
- retirement.rs