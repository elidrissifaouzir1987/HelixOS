---
type: "evidence"
date: "2026-07-14T12:33:17.447176+00:00"
question: "PLAN-005 T091 what did the controlled physical Mac mini M4 benchmark establish and why does PERF-002 remain pending?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["durable_dispatch_benchmark.rs", "m4-benchmark.md", "m4-raw.json", "PERF-002", "SC-005"]
---

# Q: PLAN-005 T091 what did the controlled physical Mac mini M4 benchmark establish and why does PERF-002 remain pending?

## Answer

On 2026-07-14 the qualified physical Mac mini M4 profile was Apple M4 model Mac16,10, 16 GiB, macOS 26.5.2 build 25F84, arm64, with the actual temporary-store volume on internal solid-state APFS, FileVault observed on and SMART verified. The locked release controlled-benchmark completed 500 warmups plus 10000 measured final-guard-to-consumed-receipt cycles and exactly 10500 committed EXECUTING receipts. Independent nearest-rank validation found p50 58.029834 ms, p95 66.797000 ms, p99 83.636542 ms and max 289.463209 ms. The 50 ms p95 requirement failed while the 100 ms p99 requirement passed. The create-only raw JSON is 165212 bytes with SHA-256 fcf86188a41c49a4ef2def0116e614cde8125e5164be95f2a5916bfc94738983. The run came from a local working tree rather than an exact immutable commit, and the raw schema deliberately labels itself diagnostic. T091 is complete as an honest physical diagnostic, but PERF-002 and aggregate PLAN-005 claim_status remain pending; no power-loss, F_FULLFSYNC, approved at-rest, physical-isolation or Tier 1 claim follows.

## Outcome

- Signal: useful

## Source Nodes

- durable_dispatch_benchmark.rs
- m4-benchmark.md
- m4-raw.json
- PERF-002
- SC-005