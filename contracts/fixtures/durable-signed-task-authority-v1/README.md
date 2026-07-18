# Durable Signed Task Authority v1 Fixture Corpus

This directory is the versioned, language-neutral PLAN-006 corpus for
`HumanRequestGrantV1`, `TaskLeaseV1`, `ApprovalDecisionV1` and their derived current
projection bindings.

The US1 vectors use reviewed synthetic public keys and exact RFC 8785 bytes. The corpus
contains no private key, seed, authentication assertion, bearer value, real message or
native path. It is test evidence only: loading a fixture never creates a current
authority marker or permits a host effect.

## Inventory

- `cases.json`: contract-local positive, negative and tamper case inventory.
- `chain-cases.json`: cross-contract, ancestry, decision and projection case inventory.
- `expected-outcomes.json`: exact one-to-one closed outcome projection.
- `public-keys.json`: reviewed synthetic public verification material only.
- `golden/`: exact canonical protected and envelope bytes for the US1 grant/root pair.

The normative sources are under
`specs/006-durable-signed-task-authority/contracts/`. Fixtures are evidence, never
authority, and cannot issue a lease, approval, plan, preparation, dispatch or host
effect. Common fixture semantics must remain byte-identical on macOS arm64, Linux x64
and Windows x64.
