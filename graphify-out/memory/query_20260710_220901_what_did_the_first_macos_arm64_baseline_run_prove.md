---
type: "query"
date: "2026-07-10T22:09:01.426369+00:00"
question: "What did the first macOS arm64 baseline run prove and fail?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["openssl_strict_verify_accepts_chain", "Kernel", "SqliteReplayClaimantV1"]
---

# Q: What did the first macOS arm64 baseline run prove and fail?

## Answer

On the clean master checkout with Rust 1.96.1 for aarch64-apple-darwin, locked metadata, cargo check for the full workspace, and strict Clippy all passed. cargo fmt --all -- --check failed only on pre-existing legacy MVP-0 formatting drift and changed no source. The full workspace tests passed every Rust test and doctest except helixos-provision::tests::openssl_strict_verify_accepts_chain: on macOS the test selected LibreSSL 3.3.6 even though it claims OpenSSL 3.x semantics, then failed with error 53 at the CA. A rerun skipping only that external-tool mismatch passed the complete remaining workspace. Do not label the unfiltered baseline fully green until the OpenSSL-versus-LibreSSL gate is corrected or run against a real OpenSSL 3 binary.

## Outcome

- Signal: useful

## Source Nodes

- openssl_strict_verify_accepts_chain
- Kernel
- SqliteReplayClaimantV1