---
type: "implementation_result"
date: "2026-07-11T23:07:51.123560+00:00"
question: "How was Feature 004 T077 corrected to measure a real production preparation commit?"
contributor: "graphify"
outcome: "corrected"
correction: "The earlier direct-SQL benchmark bypassed signed-plan verification, final comparison, the production commit adapter and full reopen; it was removed rather than accepted as performance evidence."
source_nodes: ["ControlledBenchmarkCaseV1", "prepare_plan_v1", "SqliteCoordinatorStoreV1", "durable_preparation_benchmark.rs"]
---

# Q: How was Feature 004 T077 corrected to measure a real production preparation commit?

## Answer

T077 now uses a non-default controlled-benchmark feature. Unique Ed25519-signed plans are authenticated and made eligible outside measurement; budget scopes are preprovisioned outside measurement; each sample consumes the real prepare_plan_v1 orchestration and SqliteCoordinatorStoreV1 commit path with an absolute caller-owned monotonic deadline. Public synthetic L2 irreversible plans prove zero recovery-provider calls, so recovery transfer remains a separate artifact. A two-operation smoke test survives a full production reopen with retained root identity and historical key resolver. The example has six passing tests, strict clippy passes, dirty worktrees refuse before root or output creation, and runtime detection requires an Apple M4 macOS arm64 host.

## Outcome

- Signal: corrected
- Correction: The earlier direct-SQL benchmark bypassed signed-plan verification, final comparison, the production commit adapter and full reopen; it was removed rather than accepted as performance evidence.

## Source Nodes

- ControlledBenchmarkCaseV1
- prepare_plan_v1
- SqliteCoordinatorStoreV1
- durable_preparation_benchmark.rs