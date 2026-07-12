---
type: "query"
date: "2026-07-12T11:02:24.936056+00:00"
question: "What corrected the final intermittent Windows PLAN-001 and PLAN-004 hosted test failures?"
contributor: "graphify"
outcome: "corrected"
correction: "Use explicit diagnostic classes and a hosted correctness window without accepting Unclassified; normalize source-only CRLF before multiline guards; never change production or SC-010 timing."
source_nodes: ["contention.rs", "portability.rs", "maintenance.rs", "commit_synthetic_preparation_until_v1"]
---

# Q: What corrected the final intermittent Windows PLAN-001 and PLAN-004 hosted test failures?

## Answer

The b661139 Windows run failed one 64-thread smoke with zero acknowledged commits, but the same code passed twice on Windows at 17acebb in about five seconds. The failed test collapsed unavailable, unhealthy, deadline and unclassified outcomes and asserted before reading durable state. Keep every non-Committed/non-Conflict class as a failure, expose the closed redacted class vector plus durable observation, and widen only the T042 test correctness window to a 30-second SQLite busy cap inside a 60-second absolute deadline. Production bounds and the strict SC-010 40 ms + 50 ms oracle remain unchanged. A separate deterministic Windows failure came from an LF-specific split in portability.rs over CRLF checkout bytes; normalize that included maintenance source to LF before the exact source guard.

## Outcome

- Signal: corrected
- Correction: Use explicit diagnostic classes and a hosted correctness window without accepting Unclassified; normalize source-only CRLF before multiline guards; never change production or SC-010 timing.

## Source Nodes

- contention.rs
- portability.rs
- maintenance.rs
- commit_synthetic_preparation_until_v1