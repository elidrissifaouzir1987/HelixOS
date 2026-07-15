---
type: "implementation_result"
date: "2026-07-15T03:52:08.993720+00:00"
question: "Why did PLAN-005 hosted Windows run 29386887090 fail its portability gate, and what corrected the false negative?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat source-text semantic assertions as line-ending agnostic; reserve raw byte equality for explicitly pinned immutable artifacts."
source_nodes: ["portability.rs", "lib.rs"]
---

# Q: Why did PLAN-005 hosted Windows run 29386887090 fail its portability gate, and what corrected the false negative?

## Answer

The hosted Windows checkout converted the unpinned helix-plan-dispatch lib.rs source to CRLF, while one semantic portability assertion searched for an LF-only two-line module declaration. Normalize CRLF to LF inside that test before checking the private feature-gated module declaration; keep production sources, the workflow, frozen registries, removal manifests, and all reviewed digests unchanged.

## Outcome

- Signal: corrected
- Correction: Treat source-text semantic assertions as line-ending agnostic; reserve raw byte equality for explicitly pinned immutable artifacts.

## Source Nodes

- portability.rs
- lib.rs