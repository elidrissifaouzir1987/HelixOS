# Durable Signed Task Authority v1 Fixture Corpus

This directory is the versioned, language-neutral PLAN-006 corpus skeleton for
`HumanRequestGrantV1`, `TaskLeaseV1`, `ApprovalDecisionV1` and their derived current
projection bindings.

Phase 1 freezes only the inventory and ownership boundary. It deliberately contains no
plausible signed authority, private key, seed, authentication assertion, bearer value,
real message, native path or generated acceptance evidence. Reviewed public synthetic
keys, exact canonical wires, mutations and outcomes are added only after the
corresponding tests and implementations exist.

The empty arrays in the four JSON files are the intentional T007 setup state. They are
not a passing contract corpus, coverage claim or conformance result.

## Inventory

- `cases.json`: contract-local positive, negative and tamper case inventory.
- `chain-cases.json`: cross-contract, ancestry, decision and projection case inventory.
- `expected-outcomes.json`: exact one-to-one closed outcome projection.
- `public-keys.json`: reviewed synthetic public verification material only.
- `golden/README.md`: tracked non-authority placeholder that keeps the golden
  directory present in a fresh clone.
- `golden/`: exact canonical bytes and derived digests added by later contract and
  projection tasks.

The normative sources are under
`specs/006-durable-signed-task-authority/contracts/`. Fixtures are evidence, never
authority, and cannot issue a lease, approval, plan, preparation, dispatch or host
effect. Common fixture semantics must remain byte-identical on macOS arm64, Linux x64
and Windows x64.
