---
type: "implementation"
date: "2026-07-13T19:51:59.778871+00:00"
question: "What did the PLAN-005 T080 portable conformance half establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["conformance.rs", "end-to-end-cases.json", "DispatchFaultProbeV1"]
---

# Q: What did the PLAN-005 T080 portable conformance half establish?

## Answer

The frozen six-scenario JCS lifecycle corpus has exact durable states and separate control state, is subsystem-only and authorizes zero effects or activation. The ordinary portable dispatch, receive/consume, lost-ack receipt recovery and bounded unknown/reconciliation APIs pass with deterministic no-effect fakes. Raw fixture hashes and their JCS projection hashes are distinct and pinned; the fault fixture and authoritative registry agree exactly on 90 ordered boundaries and 180 cases, and every compiled feature-gated boundary ID selects and injects once.

## Outcome

- Signal: useful

## Source Nodes

- conformance.rs
- end-to-end-cases.json
- DispatchFaultProbeV1