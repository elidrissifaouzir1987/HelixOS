---
type: "ci-evidence"
date: "2026-07-12T09:43:11.122202+00:00"
question: "How must PLAN-001 T028 and PLAN-002 T035 publish immutable CI evidence without promoting pull-request validation?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["PLAN-001", "PLAN-002", "contracts.yml", "plan-eligibility.yml"]
---

# Q: How must PLAN-001 T028 and PLAN-002 T035 publish immutable CI evidence without promoting pull-request validation?

## Answer

Both three-platform workflows must upload a retained per-platform descriptor and use the exact actions/upload-artifact output digest as the actions/attest subject. Pull requests upload validation artifacts but deliberately skip attestations; only push or workflow_dispatch runs may require and publish attestation IDs and URLs. Every immutable run fails closed when artifact ID, URL, SHA-256 digest, attestation outcome, attestation ID or attestation URL is missing. PLAN-001 descriptors bind runner image and OS/architecture, Rust/Cargo/Python/check-jsonschema/OpenSSL identities and reviewed schema/corpus digests. PLAN-002 descriptors bind runner image and OS/architecture, Rust/Cargo identity and the frozen expected-outcomes digest. Catalog claims remain pending until one unchanged commit has three green jobs and independently verified artifact digests and attestations.

## Outcome

- Signal: useful

## Source Nodes

- PLAN-001
- PLAN-002
- contracts.yml
- plan-eligibility.yml