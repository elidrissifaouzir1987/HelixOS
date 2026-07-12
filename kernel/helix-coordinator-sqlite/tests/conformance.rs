//! The SQLite adapter consumes the exact same host-independent Feature 004 corpus.

// Reusing the portable decoder is intentional: per-platform or per-adapter expected
// files would permit semantic drift between the protocol and its first store adapter.
#[path = "../../helix-plan-preparation/tests/conformance.rs"]
mod frozen_portable_corpus;
