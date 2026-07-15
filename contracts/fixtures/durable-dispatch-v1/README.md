# Durable Dispatch v1 Fixture Corpus

This directory freezes the portable parametric corpus for the PLAN-005 grant and receipt
contracts. The normative structures remain the reviewed Draft 2020-12 schemas under
`specs/005-durable-dispatch/contracts/`.

## Files

- `cases.json` contains five signed base envelopes, the two public verification keys,
  the closed mutation vocabulary, exhaustive protected-field inventories and stable
  mutation case IDs.
- `expected-outcomes.json` maps every case ID exactly once to a closed result, stage,
  reason and authority class.

The bases cover one valid grant, one valid `CONSUMED` receipt and all three valid
post-`RECEIVED` `REFUSED_DEFINITE` reasons. The mutation inventory removes every one
of the 69 grant and 25 receipt protected fields, then covers outer-envelope members,
unknown/duplicate/non-canonical/oversized wire, digest/signature/profile failures,
deadline and binding failures, invalid decision shapes, and the four pre-`RECEIVED`
codes that can never serialize as receipts.

## Runner contract

A runner selects `base`, applies the one closed mutation, performs strict canonical
decode and verification, and compares the result with the same ID in
`expected-outcomes.json`. `raw-transform` operates on bytes before JSON parsing.
No platform branch may change a case or outcome.

The signatures were produced by ephemeral Ed25519 signers during initial creation and
the recorded Phase 2 semantic correction. Only the current fixed public keys and
signature bytes are retained. No private key, seed, credential, native path, user
content or regeneration authority exists in this corpus. These fixtures authorize no
host effect and remain synthetic no-effect evidence.

Tests must assert 69/69 and 25/25 field coverage, unique IDs, exact one-to-one outcome
mapping, distinct grant/receipt signer purposes and unchanged bytes on macOS arm64,
Linux x86_64 and Windows x64.
