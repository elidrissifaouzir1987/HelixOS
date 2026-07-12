---
type: "query"
date: "2026-07-12T12:28:51.328270+00:00"
question: "What did the later hosted Windows rerun correct about the PLAN-003 concurrent-initializer diagnosis?"
contributor: "graphify"
outcome: "corrected"
correction: "The 5,000 ms fixture budget alone did not change the independent 1,000-poll setup-gate cutoff; raise only that deadline-checked cutoff to 5,000 and retain every convergence assertion."
source_nodes: ["concurrent_empty_root_initializers_converge_on_one_complete_schema()", "initialize_or_verify_store()", "acquire_setup_gate_with_clock()", "MAX_SETUP_GATE_ATTEMPTS"]
---

# Q: What did the later hosted Windows rerun correct about the PLAN-003 concurrent-initializer diagnosis?

## Answer

Expanded graph vocabulary: concurrent initializer, setup gate, busy, deadline, Windows, schema, conformance, retry, root lease, SQLite. The earlier fixture-only change from 250 ms to 5,000 ms was incomplete: run 29192411636 returned the now-visible STORE_BUSY from the direct eight-initializer test. The process-local gate serialized SQLite setup but independently stopped after 1,000 one-millisecond polls; the 3.86-second binary ended too early for the later 5,000 ms root or SQLite budgets to be exhausted. Raise only MAX_SETUP_GATE_ATTEMPTS to 5,000, keep the configured/deadline clamp and every clock check, preserve all SQLite/root-lease/SC-004 limits, and continue requiring every initializer plus a healthy reopen.

## Outcome

- Signal: corrected
- Correction: The 5,000 ms fixture budget alone did not change the independent 1,000-poll setup-gate cutoff; raise only that deadline-checked cutoff to 5,000 and retain every convergence assertion.

## Source Nodes

- concurrent_empty_root_initializers_converge_on_one_complete_schema()
- initialize_or_verify_store()
- acquire_setup_gate_with_clock()
- MAX_SETUP_GATE_ATTEMPTS