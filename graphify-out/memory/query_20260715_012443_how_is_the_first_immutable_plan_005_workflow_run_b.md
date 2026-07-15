---
type: "implementation-result"
date: "2026-07-15T01:24:43.924356+00:00"
question: "How is the first immutable PLAN-005 workflow run bootstrapped before durable-dispatch.yml exists on the default branch?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["T094", "durable-dispatch.yml"]
---

# Q: How is the first immutable PLAN-005 workflow run bootstrapped before durable-dispatch.yml exists on the default branch?

## Answer

Use the exact successful push run for codex/plan-005-durable-dispatch. GitHub manual workflow_dispatch is unavailable until the workflow file exists on the default branch; the branch push trigger therefore supplies the first immutable source-SHA run without modifying master. After merge, workflow_dispatch is available normally.

## Outcome

- Signal: useful

## Source Nodes

- T094
- durable-dispatch.yml