---
type: "implementation"
date: "2026-07-11T10:47:27.015515+00:00"
question: "How does the PLAN-004 T049 private process probe guarantee bounded cleanup and redacted diagnostics?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["process_probe.rs", "SynchronizedProcessProbeV1", "ProcessProbeChildV1", "contention.rs"]
---

# Q: How does the PLAN-004 T049 private process probe guarantee bounded cleanup and redacted diagnostics?

## Answer

tests/common/process_probe.rs now owns current-test-binary re-exec, private environment transport, indexed READY/GO/result markers, 30-second protocol deadlines, early-child-exit detection, ordered results, and Drop cleanup that kills then waits every remaining child before deleting the probe root. Debug for environment, child, parent and errors omits native paths. A standalone two-child real re-exec harness passed and the helper passed clippy-driver with -D warnings.

## Outcome

- Signal: useful

## Source Nodes

- process_probe.rs
- SynchronizedProcessProbeV1
- ProcessProbeChildV1
- contention.rs