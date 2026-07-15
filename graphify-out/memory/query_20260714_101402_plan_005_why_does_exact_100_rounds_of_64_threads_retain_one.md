---
type: "query"
date: "2026-07-14T10:14:02.639659+00:00"
question: "Why does exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round panic with ROOT_BUSY while opening strict coordinator V2, and what is the smallest correct fix?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["dispatch_end_to_end_contention.rs", "CoordinatorDescriptorV1", "PreparedCoordinatorRootV1", "acquire_existing_root_lease"]
---

# Q: Why does exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round panic with ROOT_BUSY while opening strict coordinator V2, and what is the smallest correct fix?

## Answer

Expanded from graph vocabulary: [dispatch, contention, root, busy, strict, coordinator, sqlite, lease, worker, open, threads, rounds]. This is a test-harness lifecycle failure, not a production root-lease defect. The barrier releases 64 workers into CoordinatorDescriptorV1::open_store_v1 after PreparedCoordinatorRootV1::force_last_close_v1 removed the WAL anchor. Each strict V2 open correctly takes the exclusive advisory root lease and performs full V2 verification; the fixed test clock leaves only 4,900 effective 1 ms acquisition attempts despite a 30,000 ms configured cap, so tail workers may return the intended ROOT_BUSY refusal. The smallest semantics-preserving correction is to retain sequential, table-touched idle coordinator and adapter WAL anchors through all worker joins and durable observation, then call force_last_close_v1 immediately before assert_restart_checkpoint_v1 and reopen the anchors afterward. Apply the same lifecycle ordering to the 8-process round. Do not weaken production locking or accept ROOT_BUSY, and do not merely raise production/deadline limits; synchronized dispatch/consume and a genuine last-close strict reopen remain intact.

## Outcome

- Signal: useful

## Source Nodes

- dispatch_end_to_end_contention.rs
- CoordinatorDescriptorV1
- PreparedCoordinatorRootV1
- acquire_existing_root_lease
