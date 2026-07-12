---
type: "query"
date: "2026-07-12T12:16:51.102239+00:00"
question: "Why did the Windows PLAN-003 initialization-concurrent corpus case fail while the dedicated eight-initializer test passed?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat initialization-concurrent as a correctness fixture with the existing 5,000 ms hosted scheduling budget and preserve production timing limits; always surface the closed error code."
source_nodes: ["every_corpus_case_is_executed_or_explicitly_blocked_by_a_missing_seam()", "initialize_or_verify_store()", "concurrent_empty_root_initializers_converge_on_one_complete_schema()", "conformance_execution.rs"]
---

# Q: Why did the Windows PLAN-003 initialization-concurrent corpus case fail while the dedicated eight-initializer test passed?

## Answer

Expanded graph vocabulary: initialization, concurrent, setup gate, busy, deadline, SQLite, Windows, conformance, corpus, schema. The process-local CONNECTION_SETUP_GATES mutex serialized both corpus workers before SQLite, so this was not the cold WAL/shm race. The corpus used a 250 ms scheduling budget while the dedicated correctness fixture already used 5,000 ms; an overloaded Windows runner could exhaust the setup-gate wait and return STORE_BUSY, which the panic hid. Align only this correctness fixture to 5,000 ms and include the closed error code in diagnostics. Production keeps its 1,000-attempt cap, and both initializers plus full healthy reopen remain mandatory.

## Outcome

- Signal: corrected
- Correction: Treat initialization-concurrent as a correctness fixture with the existing 5,000 ms hosted scheduling budget and preserve production timing limits; always surface the closed error code.

## Source Nodes

- every_corpus_case_is_executed_or_explicitly_blocked_by_a_missing_seam()
- initialize_or_verify_store()
- concurrent_empty_root_initializers_converge_on_one_complete_schema()
- conformance_execution.rs