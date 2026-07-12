---
type: "query"
date: "2026-07-12T11:28:17.486823+00:00"
question: "How should restore_maintenance_api source guards handle CRLF on Windows without weakening semantics?"
contributor: "graphify"
outcome: "corrected"
correction: "Normalize the test's embedded maintenance source to LF once per source-order test; preserve every exact semantic assertion and all production code."
source_nodes: ["source_guard_normalization_is_lf_and_crlf_independent()", "windows_refusal_precedes_package_handle_trust_and_every_mutation()", "maintenance.rs"]
---

# Q: How should restore_maintenance_api source guards handle CRLF on Windows without weakening semantics?

## Answer

Expanded from the graph vocabulary via [restore, maintenance, source, guards, crlf, windows, normalize, semantics, refusal, rotation]. The failures were byte-level source guard mismatches: include_str! observed CRLF checkout bytes while exact patterns embedded LF. Normalize only the included maintenance source from CRLF to LF before all multiline find/contains/slice assertions. Keep LIB_SOURCE and the failure/quarantine scans unchanged because their delimiters are single-line, and do not change any production restore, custody, refusal, rotation, or activation behavior.

## Outcome

- Signal: corrected
- Correction: Normalize the test's embedded maintenance source to LF once per source-order test; preserve every exact semantic assertion and all production code.

## Source Nodes

- source_guard_normalization_is_lf_and_crlf_independent()
- windows_refusal_precedes_package_handle_trust_and_every_mutation()
- maintenance.rs