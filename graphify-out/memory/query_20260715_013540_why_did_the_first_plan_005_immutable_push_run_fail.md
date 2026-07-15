---
type: "ci-correction"
date: "2026-07-15T01:35:40.055236+00:00"
question: "Why did the first PLAN-005 immutable push run fail in the path and evidence policy job?"
contributor: "graphify"
outcome: "corrected"
correction: "Any CI job that validates the frozen removal manifest must check out enough Git history to resolve and hash the baseline commit and tree."
source_nodes: ["durable-dispatch.yml", "plan005_removal_drill.py", "T094"]
---

# Q: Why did the first PLAN-005 immutable push run fail in the path and evidence policy job?

## Answer

Run 29381923952 checked out only depth 1, so the evidence tests could not resolve frozen removal baseline commit 6f8dfdd5194792e8592cd10ebaaf8828833effbe. Adding fetch-depth: 0 to the path-policy checkout and a scoped regression test restored access to the exact baseline while keeping credentials disabled.

## Outcome

- Signal: corrected
- Correction: Any CI job that validates the frozen removal manifest must check out enough Git history to resolve and hash the baseline commit and tree.

## Source Nodes

- durable-dispatch.yml
- plan005_removal_drill.py
- T094