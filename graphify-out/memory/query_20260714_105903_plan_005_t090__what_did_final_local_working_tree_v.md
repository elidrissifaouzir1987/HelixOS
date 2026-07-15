---
type: "validation-result"
date: "2026-07-14T10:59:03.893946+00:00"
question: "PLAN-005 T090: what did final local working-tree validation establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["local-validation.md", "tasks.md", "durable-dispatch.yml"]
---

# Q: PLAN-005 T090: what did final local working-tree validation establish?

## Answer

Pinned Rust format, locked workspace check, strict all-feature Clippy, workspace and focused suites, three exact end-to-end cardinality gates, nine public ignored release gates, a 143-case six-scenario no-effect corpus, 55 evidence-tool tests, nine JSON inputs, both SQL schemas, Actionlint, roadmap and diff controls passed locally. The result is working-tree evidence based on baseline HEAD 6f8dfdd, not clean-commit or immutable release evidence. The 27 excluded user paths remained unchanged and claim_status remains pending-evidence.

## Outcome

- Signal: useful

## Source Nodes

- local-validation.md
- tasks.md
- durable-dispatch.yml