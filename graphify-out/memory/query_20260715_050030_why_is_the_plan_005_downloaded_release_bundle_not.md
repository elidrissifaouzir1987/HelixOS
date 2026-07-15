---
type: "correction"
date: "2026-07-15T05:00:30.772554+00:00"
question: "Why is the PLAN-005 downloaded release bundle not recorded as a second full local verifier pass on macOS?"
contributor: "graphify"
outcome: "corrected"
correction: "Separate builder-host live toolchain equality from portable post-download verification and never convert a cross-host stop into a PASS."
source_nodes: ["plan005_supply_chain.py", "ci-immutable-bf6f178ff605b0541b5b5dabe9c4609af0218da9.md"]
---

# Q: Why is the PLAN-005 downloaded release bundle not recorded as a second full local verifier pass on macOS?

## Answer

The release bundle retains Ubuntu x86_64 Rust and Cargo verbose host output, Python 3.12.3, cargo tree bytes, and Linux evidence-tool binary digests. The exact verifier therefore stops at its live-toolchain equality check on macOS ARM64 with Python 3.9.6 and Mach-O tools. Record the full exact PASS only for the immutable Ubuntu release job before upload and attestation; independently record the downloaded ZIP digests, attestations, manifest, and host-independent semantic validators as passing, without claiming a second full local PASS or Linux runtime availability.

## Outcome

- Signal: corrected
- Correction: Separate builder-host live toolchain equality from portable post-download verification and never convert a cross-host stop into a PASS.

## Source Nodes

- plan005_supply_chain.py
- ci-immutable-bf6f178ff605b0541b5b5dabe9c4609af0218da9.md