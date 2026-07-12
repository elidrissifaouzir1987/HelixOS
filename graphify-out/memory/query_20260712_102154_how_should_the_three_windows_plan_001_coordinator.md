---
type: "query"
date: "2026-07-12T10:21:54.984317+00:00"
question: "How should the three Windows PLAN-001 coordinator test failures be corrected without weakening fail-closed behavior?"
contributor: "graphify"
outcome: "corrected"
correction: "Keep production custody and non-Unix refusal unchanged; make tests exercise retained-handle and explicit platform semantics, and normalize source-only line endings."
source_nodes: ["root_safety.rs", "test_fault.rs", "read_exact_file()", "inspect_validated_existing_restore_root_custody_v1()"]
---

# Q: How should the three Windows PLAN-001 coordinator test failures be corrected without weakening fail-closed behavior?

## Answer

Expanded from the graph vocabulary via [root, safety, restore, custody, marker, identity, windows, fault, source, inspection, transactional, phases]. Read the initializing marker through the already-retained custody handle instead of reopening the exclusively locked path; assert ROOT_IDENTITY_MISMATCH only where Unix retained-directory inspection can inspect the marker and assert the intentional ROOT_UNAVAILABLE fail-closed refusal on non-Unix; normalize include_str source from CRLF to LF before multiline call-site guards. The three targeted macOS tests, formatting, and strict all-target Clippy pass. A local Windows cross-check reached libsqlite3-sys but could not compile bundled SQLite because the macOS host lacks the Windows MSVC C sysroot.

## Outcome

- Signal: corrected
- Correction: Keep production custody and non-Unix refusal unchanged; make tests exercise retained-handle and explicit platform semantics, and normalize source-only line endings.

## Source Nodes

- root_safety.rs
- test_fault.rs
- read_exact_file()
- inspect_validated_existing_restore_root_custody_v1()