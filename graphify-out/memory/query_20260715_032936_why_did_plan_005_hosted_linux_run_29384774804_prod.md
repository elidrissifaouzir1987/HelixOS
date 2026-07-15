---
type: "ci-concurrency-diagnosis"
date: "2026-07-15T03:29:36.614024+00:00"
question: "Why did PLAN-005 hosted Linux run 29384774804 produce only 61 of 63 prior-exact outcomes in the 100 by 64 thread gate, and what corrected the CI harness?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep production root leases, deadlines, cardinalities, and strict assertions unchanged; execute the three exact hosted contention matrices in the release profile and pin that policy in tests."
source_nodes: ["exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round", "CoordinatorRootLeaseV1", "open_bound_existing_connection", "Plan005WorkflowTests"]
---

# Q: Why did PLAN-005 hosted Linux run 29384774804 produce only 61 of 63 prior-exact outcomes in the 100 by 64 thread gate, and what corrected the CI harness?

## Answer

Each dispatch operation reacquires the exclusive coordinator root lease inside authoritative reload and commit even though the test pre-opens store handles. With the fixed synthetic interval from 100 to 5000 ms, the root lease permits 4900 one-millisecond attempts. On the slower hosted Linux debug binary, two of 64 contenders exhausted that bounded wait before a bound SQLite connection existed and correctly returned StoreUnavailable; one committed and 61 returned prior-exact. The correction keeps the 5000 ms deadline, exclusive lease, 100 rounds by 64 contenders, exact 1/63 cardinality, zero closed failures, receipt equality, restart checks, and no-effect assertions unchanged, while running all three heavy contention gates with cargo test --release. Independent release runs passed: 10000 sequential requests in 89.90 seconds, 100 by 64 in 128.10 seconds, and 20 by 8 processes in 5.23 seconds. Workflow policy now requires exactly three release-profile invocations. This corrects the earlier incomplete assumption that pre-opened test handles eliminate every strict root acquisition during the synchronized operation wave.

## Outcome

- Signal: corrected
- Correction: Keep production root leases, deadlines, cardinalities, and strict assertions unchanged; execute the three exact hosted contention matrices in the release profile and pin that policy in tests.

## Source Nodes

- exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round
- CoordinatorRootLeaseV1
- open_bound_existing_connection
- Plan005WorkflowTests