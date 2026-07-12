---
type: "implementation"
date: "2026-07-11T08:37:03.166397+00:00"
question: "How must T036 emit section-14 context and budget classification hooks without changing normative first-failure precedence?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["compare.rs", "coordinator.rs"]
---

# Q: How must T036 emit section-14 context and budget classification hooks without changing normative first-failure precedence?

## Answer

Use instrumented pure-comparison variants with one callback invoked immediately after each classified context group: groups 1-5 before live guard row 14 and groups 6-12 after successful guard validation, including the failing group. For budget preflight, evaluate binding, arithmetic, and capacity in order and emit each hook only after that group's actual Ready/fault classification; then revalidate final liveness before returning a budget refusal so lower authority rows retain precedence.

## Outcome

- Signal: useful

## Source Nodes

- compare.rs
- coordinator.rs