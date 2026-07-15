# PLAN-005 immutable CI evidence — `bf6f178ff605b0541b5b5dabe9c4609af0218da9`

## Result and scope

GitHub Actions run
[`29387761127`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127)
completed successfully from a `push`, attempt 1, on branch
`codex/plan-005-durable-dispatch`. It started at `2026-07-15T03:57:01Z` and
completed at `2026-07-15T04:46:08Z`. The run, every hosted descriptor, all four
artifact API records and all four attestations identify the exact source commit
`bf6f178ff605b0541b5b5dabe9c4609af0218da9`. The path, LF and evidence-policy
job [`87264479463`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87264479463)
also completed successfully before the matrix ran.

This record closes the immutable hosted software matrix, exact-lock supply-chain
bundle and exact-commit isolated removal-drill work for PLAN-005. It does **not**
promote the aggregate PLAN-005 claim: `conformance/catalog.yaml` remains
`pending-evidence` because the physical and external gates listed below remain
open or out of scope.

## Matrix and runner identity

| Target | Successful job | Reviewed runner | Image identity | Runner name | Rust host |
|---|---|---|---|---|---|
| Linux x86_64 | [`87264515794`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87264515794) | `ubuntu-24.04`, GitHub-hosted X64 | `ubuntu24` / `20260705.232.1` | `GitHub Actions 1000000429` | `x86_64-unknown-linux-gnu` |
| macOS arm64 | [`87264515793`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87264515793) | `macos-26`, GitHub-hosted ARM64 | `macos26` / `20260630.0213.1` | `GitHub Actions 1000000428` | `aarch64-apple-darwin` |
| Windows x64 | [`87264515784`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87264515784) | `windows-2022`, GitHub-hosted X64 | `win22` / `20260706.237.1` | `GitHub Actions 1000000427` | `x86_64-pc-windows-msvc` |
| Supply chain and removal | [`87269406541`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87269406541) | `ubuntu-24.04`, GitHub-hosted X64 | `ubuntu24` / `20260705.232.1` | `GitHub Actions 1000000430` | `x86_64-unknown-linux-gnu` |

All three matrix jobs passed pinned Rust 1.96.1 installation, scoped format and
strict workspace lint gates, the unchanged PLAN-001 through PLAN-004 prerequisite
chain, canonical grant/receipt contracts, the portable corpus and 100,000 generated
mutations. Each target also passed the exact release contention workloads of 10,000
sequential requests, 100 rounds of 64 threads and 20 rounds of 8 processes; the
reviewed migration, paused clean-subsystem restore, corruption and permanent-retention
gates; all 90 in-process plus 90 process-kill fault cases; and the 1,024-ordinary plus
32-control overload profile across 100 trials. Each job then proved that validation
had not rewritten tracked bytes before upload.

These are hosted synthetic no-effect and process-kill results. They do not constitute
a real host effect, a physical power-loss test, production-supervisor qualification,
a full-machine restore, or Tier 1 evidence.

## Immutable artifacts and attestations

The GitHub artifact API reported exactly four current, unexpired artifacts when this
record was prepared. All four use the run's 90-day retention policy and expire at
`2026-10-13T03:57:01Z`.

| Subject | Artifact (ID, bytes) | Upload ZIP SHA-256 | Attestation (Rekor index) | Preservation URL |
|---|---|---|---|---|
| Linux x86_64 | `plan-005-linux-x86_64-bf6f178ff605b0541b5b5dabe9c4609af0218da9` (`8332458950`, 47,799) | `58ac45f2f2e4b3fdd90c62e52b2fa621d4ca9e3ac37d5383ae7ff7425479d747` | [`35386312`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386312) (`2171568656`) | [artifact 8332458950](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332458950) |
| macOS arm64 | `plan-005-macos-arm64-bf6f178ff605b0541b5b5dabe9c4609af0218da9` (`8332319700`, 47,958) | `487d33e301a267b79fe5369c6361f915428d51f75f1c0ab912591525ee9a2bf4` | [`35386322`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386322) (`2171568759`) | [artifact 8332319700](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332319700) |
| Windows x64 | `plan-005-windows-x64-bf6f178ff605b0541b5b5dabe9c4609af0218da9` (`8332641362`, 47,859) | `899c2e5b8f487e16baa60e69fcf079fa25266164843032fa3f355d08e65868c1` | [`35386319`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386319) (`2171568736`) | [artifact 8332641362](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332641362) |
| Release bundle | `plan-005-release-bf6f178ff605b0541b5b5dabe9c4609af0218da9` (`8332754639`, 8,757,559) | `10802a33838c2edc53db8c9db64fed9d37c4ad10b1afb125fc6adf89a4e96025` | [`35386320`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386320) (`2171568748`) | [artifact 8332754639](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332754639) |

The separate least-privilege attestation jobs were
[`87270349532`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87270349532),
[`87270349547`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87270349547),
[`87270349560`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87270349560),
and
[`87270349561`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/job/87270349561)
for Linux, macOS, Windows and the release bundle respectively. Each resolved exactly
one current-run artifact through the GitHub API, required the exact commit-bound name,
and attested the `actions/upload-artifact` ZIP digest rather than an individual file
inside the archive.

## Downloaded-artifact verification

An independent post-download audit on macOS downloaded the four raw ZIP archives
through the GitHub artifact API. `shasum -a 256` matched every API and attestation
digest in the table above. Each ZIP then passed `gh attestation verify` with all of the
following constraints:

- repository `elidrissifaouzir1987/HelixOS`;
- signer workflow
  `elidrissifaouzir1987/HelixOS/.github/workflows/durable-dispatch.yml`;
- source digest `bf6f178ff605b0541b5b5dabe9c4609af0218da9`;
- source ref `refs/heads/codex/plan-005-durable-dispatch`; and
- denial of self-hosted runners.

The immutable Ubuntu release job executed the complete verifier in an exact, clean
checkout **before** its checkout-clean assertion, artifact upload and attestation:

```sh
python3 tools/plan005_supply_chain.py verify \
  --repository . \
  --output "$RUNNER_TEMP/plan-005-release-evidence" \
  --require-removal \
  --require-exact
```

That full command passed in job `87269406541`. It verified the complete sorted
manifest, exact source and workflow provenance, reviewed inputs, live pinned Linux
toolchain, production closure and adjacency, SBOM, licenses, bundled SQLite, RustSec
result, exact removal evidence, closed bundle file set, and secret/private-path scan.

The independent macOS audit verified the downloaded `MANIFEST.sha256` and separately
exercised every host-independent semantic validator for provenance and reviewed bytes,
the production graph, license inventory, native SQLite evidence, SBOM and release
oracles, RustSec evidence, exact removal evidence, the closed file set and the
secret/private-path scan. Those host-independent checks passed. The complete local
command itself stopped only at its deliberately host-bound live-toolchain comparison
with `retained toolchain output differs from live pinned tool`: the retained toolchain
and `cargo tree` bytes were produced on the immutable Linux runner, while the audit
host was macOS.

Accordingly, this record does **not** claim a second full local verifier pass and does
not claim that a Linux runtime was available to the independent macOS audit. The full
exact verifier result is the successful immutable Ubuntu job; the post-download audit
independently binds and semantically checks the portable portions of that artifact.

## Exact-lock supply-chain result

The normalized CycloneDX 1.5 all-target SBOM covers the exact 84-package, four-root
production Cargo closure and all 143 normal/build dependency edges, including the
explicit bundled SQLite native component. The inventory covers all 77 external and 7
workspace packages and retains 10 canonical SPDX license texts plus applicable package
license files.

The bundle pins and records:

- Rust `1.96.1`, `cargo-cyclonedx 0.5.9` and `cargo-audit 0.22.2`;
- RustSec database revision
  `6e3286f4efa8c142fb33e5ea4342c8db6693cf34` and SPDX license-list-data
  revision `c4a7237ec8f4654e867546f9f409749300f1bf4c`;
- RustSec scan timestamp `2026-07-15T04:42:20Z`, 220 locked dependencies,
  zero vulnerabilities and one retained informational unmaintained warning,
  `RUSTSEC-2025-0134` for `rustls-pemfile 2.2.0`;
- `rusqlite 0.40.1`, `libsqlite3-sys 0.38.1` and bundled SQLite `3.53.2`
  with source ID
  `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`;
- crate archive SHA-256
  `f6c19a05435c21ac299d71b6a9c13db3e3f47c520517d58990a462a1397a61db`,
  `sqlite3.c` SHA-256
  `0a409f1633283fa31a9126b11fbfd64a1991c5d30defad07e5745d4667f5e23d`,
  and `sqlite3.h` SHA-256
  `9e69a1353a4288450b0d5239ede11fc7f1f4c8e5eb07491fc8317eacb5b7de7e`;
- the exact resolved `bundled` static-link feature profile for `rusqlite` and
  `libsqlite3-sys`, with forbidden SQLCipher, loadable-extension, Gecko and
  build-time-bindgen feature families absent;
- full scanner output, empty scanner stderr, runner/toolchain/workflow provenance and
  the reviewed workflow digest
  `855a7ee853acb3a9029c9e134b2dfcfa2b3f2752cfb3492b02be33272ba3fe0d`;
  and
- the exact reviewed `Cargo.lock` digest
  `f18941ac90749f8eb9adffc2e4e9b91e1d9705da8c0cad0c9fe53b451759ff4d`.

## Removal-drill result

The release job executed the drill in a detached exact-commit worktree and recorded
`passing-isolated-exact-commit-removal`. The source commit tree was
`338db095d80b54eedaad3059c214b10aaa71ef01`; the frozen pre-PLAN-005 baseline was
commit `6f8dfdd5194792e8592cd10ebaaf8828833effbe`, tree
`d1f51cc3ba5d0e42ade27fb9aefda01750093971`. After removal, the staged index tree
equalled that same baseline tree.

The report proves:

- all 495 protected baseline files were restored exactly, with protected-manifest
  SHA-256
  `090cb94b6cf3c5c3f005931ef22635558a18e689c171b690010955e1125f4cf8`;
- 23 baseline paths were restored, 168 PLAN-005-added executable/derived paths were
  removed, 35 audit-only paths were retained, and the post-removal inventory contained
  530 files;
- post-removal Cargo metadata contained exactly the eight PLAN-001 through PLAN-004
  and legacy workspace packages;
- metadata plus all five prerequisite/legacy test command groups completed with exit
  code zero, no test was skipped, and retained logs bind each command result; and
- `immutable_release_evidence_eligible` and `sc009_exact_commit_eligible` were both
  `true`, while the closed source inventory found no PLAN-005 executable dispatch
  surface after removal.

This is an isolated software source-removal proof. It is not secure erasure,
production-state decommissioning, a proof about retained live authority, or a
full-machine removal result.

## Limits that remain pending

The controlled physical Mac mini M4 result remains separate local working-tree
evidence. This immutable hosted run does not convert it into exact-commit immutable
physical evidence and does not add physical power-loss or `F_FULLFSYNC` provenance.

The following remain outside this immutable software result and keep the aggregate
PLAN-005 claim at `pending-evidence`:

- physical power-loss and `F_FULLFSYNC` durability evidence;
- external approval of the production-root encrypted-at-rest profile;
- production supervisor, IPC/provider integration and physical isolation, which are
  outside this feature's implementation scope;
- real host effects or execution-success claims;
- full-machine restore, activation and secure erasure; and
- Tier 1 support and the required external operational evidence.
