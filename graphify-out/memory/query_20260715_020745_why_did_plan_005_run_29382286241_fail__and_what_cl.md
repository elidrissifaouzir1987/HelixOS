---
type: "ci-remediation"
date: "2026-07-15T02:07:45.888815+00:00"
question: "Why did PLAN-005 run 29382286241 fail, and what closed remediation is ready for the next immutable run?"
contributor: "graphify"
outcome: "corrected"
correction: "The first stable-Windows proposal used file-id by path and could reopen a substituted object. It was replaced before publication by fs-id on one no-follow live handle, binding type, reparse status, and high-resolution identity to the same object."
source_nodes: ["helix-dispatch-inbox-sqlite", "helix-coordinator-sqlite", "durable-dispatch"]
---

# Q: Why did PLAN-005 run 29382286241 fail, and what closed remediation is ready for the next immutable run?

## Answer

Run 29382286241 proved the path policy but exposed three platform defects: Linux strict Clippy compiled a macOS-only benchmark parser without a cfg guard; Windows Rust 1.96.1 rejected unstable MetadataExt identity methods; macOS prerequisite testing found the DISPATCHING state literal outside the dispatch-prefixed source partition. The corrected source adds the exact macOS cfg, centralizes the state code in dispatch_schema, and on Windows opens each path with BACKUP_SEMANTICS plus OPEN_REPARSE_POINT, then reads type, reparse status, and the 128-bit fs-id identity from the same live handle. The fs-id dependency is exactly pinned at 0.2.0. Deterministic supply oracles are 84 packages, 143 edges, 77 external packages, 7 workspace packages; a fresh 280-file supply bundle built and verified twice. Local PLAN-004 and PLAN-005 Python suites, portability tests, workspace check, strict workspace Clippy, and an isolated x86_64-pc-windows-msvc helper check pass. The hosted Windows matrix remains the required end-to-end oracle; no directory-fsync, power-loss, full-machine, or Tier-1 claim is added.

## Outcome

- Signal: corrected
- Correction: The first stable-Windows proposal used file-id by path and could reopen a substituted object. It was replaced before publication by fs-id on one no-follow live handle, binding type, reparse status, and high-resolution identity to the same object.

## Source Nodes

- helix-dispatch-inbox-sqlite
- helix-coordinator-sqlite
- durable-dispatch