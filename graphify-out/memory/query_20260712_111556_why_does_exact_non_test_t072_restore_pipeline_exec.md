---
type: "query"
date: "2026-07-12T11:15:56.850728+00:00"
question: "Why does exact_non_test_t072_restore_pipeline_executes_end_to_end return restore-platform-unsupported on Windows?"
contributor: "graphify"
outcome: "corrected"
correction: "Preserve the Windows production refusal; correct only the conformance harness so Windows expects the exact refusal and non-Windows expects success."
source_nodes: ["exact_non_test_t072_restore_pipeline_executes_end_to_end()", "production_restore_conformance.rs", "maintenance.rs"]
---

# Q: Why does exact_non_test_t072_restore_pipeline_executes_end_to_end return restore-platform-unsupported on Windows?

## Answer

Expanded from the graph vocabulary via [exact, restore, pipeline, platform, unsupported, windows, production, conformance, executes]. The production refusal is intentional and reviewed: Windows v1 must return restore-platform-unsupported before package capture, PAUSE, or destination mutation because retained-handle identity is unavailable. The defect was the external production_restore_conformance harness requiring success on every host; it must assert the fixed Windows refusal and success elsewhere without changing production semantics.

## Outcome

- Signal: corrected
- Correction: Preserve the Windows production refusal; correct only the conformance harness so Windows expects the exact refusal and non-Windows expects success.

## Source Nodes

- exact_non_test_t072_restore_pipeline_executes_end_to_end()
- production_restore_conformance.rs
- maintenance.rs