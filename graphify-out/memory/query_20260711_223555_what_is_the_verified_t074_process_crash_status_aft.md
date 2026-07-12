---
type: "implementation_result"
date: "2026-07-11T22:35:55.050344+00:00"
question: "What is the verified T074 process-crash status after restoring the explicit maintenance fault probe?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["run_t074_production_fault_probe_v1", "release_process_kill_matrix_reopens_to_one_closed_state", "FaultProbeV1"]
---

# Q: What is the verified T074 process-crash status after restoring the explicit maintenance fault probe?

## Answer

The frozen registry remains exact at 123 boundaries and 167 controlled cases. Backup and restore production conformance each pass, and an explicit caller-owned probe now reaches their production maintenance hooks. The release process_crash matrix is still RED: it exits before the first selected non-maintenance boundary because 86 boundaries across portable preparation, recovery, commit, readback, failure and retirement do not yet carry the explicit session. The current partial harness is not exhaustive process-kill evidence and T074 remains unchecked.

## Outcome

- Signal: useful

## Source Nodes

- run_t074_production_fault_probe_v1
- release_process_kill_matrix_reopens_to_one_closed_state
- FaultProbeV1