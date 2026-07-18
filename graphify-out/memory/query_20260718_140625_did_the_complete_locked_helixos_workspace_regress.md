---
type: "test-outcome"
date: "2026-07-18T14:06:25.310713+00:00"
question: "Did the complete locked HelixOS workspace regress after PLAN-006 US1 root issuance?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["kernel/Cargo.toml", "specs/006-durable-signed-task-authority/evidence/us1-request.md"]
---

# Q: Did the complete locked HelixOS workspace regress after PLAN-006 US1 root issuance?

## Answer

No. On 2026-07-18, cargo test --locked --workspace --all-targets completed with exit 0 after the T025-T038 implementation. This included all PLAN-006 contract/core/SQLite tests, prior-plan crates, kernel and MCP shim integration, and the older end-to-end dispatch contention segment (24 passed, 1 ignored, 519.36 seconds). The targeted three-crate strict Clippy run, scoped format check, roadmap check, and diff check also passed. This is local macOS arm64 evidence only; immutable and cross-platform claims remain pending.

## Outcome

- Signal: useful

## Source Nodes

- kernel/Cargo.toml
- specs/006-durable-signed-task-authority/evidence/us1-request.md