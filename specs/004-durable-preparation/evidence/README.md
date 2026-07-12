# PLAN-004 evidence and supply-chain policy

This directory retains redacted evidence for Feature 004. Unless an artifact is listed
with an immutable commit, digest, platform and preservation URL in
`conformance/catalog.yaml`, its status is **pending evidence**. Local synthetic tests do
not establish production compensability, power-loss durability, restored-system
activation or Tier 1 readiness. A clean local physical-M4 result now exists for the
exact source commit `f7b021db52503aaedcc59b9c9c8d95d357555352`; it satisfies the local
synthetic latency thresholds but is not immutable release evidence.

## Retained clean-source local evidence

The following two create-new artifacts were produced by the controlled benchmark from
a detached worktree that was clean at start:

- `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.json`,
  SHA-256 `ed90faf0645589deb98d454466854771569eb53d69616584c092a25ae3bd1c12`;
- `benchmark-mac-mini-m4-f7b021db52503aaedcc59b9c9c8d95d357555352.recovery-transfer.json`,
  SHA-256 `da442c396f280cf21f4125498676fa52b17e68cfc97bbff0aeb1afbc1cb60e1e`.

The coordinator artifact contains 500 warmups, 10,000 raw sorted samples and 10,500
committed operations. It records p50 11,218,708 ns, p95 24,096,375 ns, p99 25,443,666
ns and maximum 26,528,459 ns; the 25 ms p95 and 100 ms p99 limits both pass. The
separate recovery artifact writes and verifies 16 MiB in 66,358,167 ns and is excluded
from coordinator percentiles. See `local-validation.md` for the complete Quickstart
§1–15 results, the first 239-operation dead end and its bounded `data_version`/hot-path
verification correction.

The local explicit-session process-kill release driver also passes all five selected
harness tests, covering 123 real fault boundaries and 167 controlled cases. This is a
local synthetic process-kill pass, not an immutable CI result and not power-loss
evidence. Both the benchmark and process-kill result still need immutable preservation,
uploaded-artifact digest binding and attestations.

The hosted run at source commit `b3132586245acea415104381b337d3fea3303444`
identified one Windows harness mismatch after every earlier Windows gate, including the
production restore-refusal oracle and release contention, had passed. The release
process-kill parent attempted a `restore` mutation boundary even though the reviewed
Windows v1 public contract had already returned `RESTORE_PLATFORM_UNSUPPORTED` before
package capture, PAUSE or destination mutation. The frozen 123-boundary/167-case
registry remains unchanged. The correction keeps all 167 cases on macOS/Linux and
partitions Windows to the exact 150 production-reachable cases after separately proving
the fail-closed refusal. The failed run, local correction evidence and hosted rerun
status are retained in `ci-remediation-local.md`. The corrected pull-request run
`29198018266` passed on macOS arm64, Linux x86_64 and Windows x64 at exact source
`2720fbe1042095d74db65f3d3fe71244cf38c810`; because it is validation-only and has no
artifact attestation, it is not promoted to immutable release evidence.

The recorded at-rest label says only that FileVault was observed enabled on the local
internal APFS volume. It does not approve an at-rest profile or establish a
cryptographic qualification.

## Pinned build and native storage inputs

- Rust toolchain: `1.96.1`, minimal profile, with `rustfmt` and `clippy`, from
  `kernel/rust-toolchain.toml`.
- Dependency resolution authority: `kernel/Cargo.lock`; release and CI commands use
  `--locked`.
- SQLite adapter: `rusqlite 0.40.1`, `default-features=false`, features `backup`,
  `bundled`, `serialize`.
- Native binding: `libsqlite3-sys 0.38.1`, bundled static SQLite `3.53.2`, source ID
  `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.
- Required runtime profile: WAL, `synchronous=FULL`, disabled automatic checkpoint,
  foreign keys on, trusted schema off, cell-size checking on and recursive triggers on.
- Windows path identity preflight: `file-id 0.2.3` using a high-resolution volume
  serial plus 128-bit file ID. Because that safe API reopens a path rather than deriving
  identity from the retained handle, clean-root restore is explicitly unsupported on
  Windows v1 and refuses before PAUSE or destination mutation.

The direct Feature 004 leaf dependencies are pinned in
`kernel/helix-coordinator-sqlite/Cargo.toml`: `base64 0.22.1`, `ed25519-dalek 2.2.0`,
`getrandom 0.4.3`, `rusqlite 0.40.1`, `serde 1.0.228`, `serde_json 1.0.150`,
`serde_json_canonicalizer 0.3.2`, `sha2 0.10.9`, the three local Helix contract crates,
and the Windows-only `file-id 0.2.3`. The reviewed transitive graph is produced with:

```sh
cargo tree --locked -p helix-coordinator-sqlite -e normal --target all
```

No system SQLite, dynamic extension, network client, async runtime or production
fallback is admitted by this feature.

## License, advisory and SBOM evidence

Before any immutable PLAN-004 claim, CI must retain all of the following for the exact
lockfile and commit:

1. a machine-readable CycloneDX or SPDX SBOM covering Rust packages, target-specific
   Windows packages and bundled SQLite source;
2. a license inventory plus source/license texts, including SQLite's public-domain
   notice and the MIT/Apache-2.0 choices used by the Rust dependency graph;
3. a RustSec advisory scan of the locked graph, with database revision, command version,
   timestamp and complete output;
4. provenance for the source commit, runner image, Rust toolchain, Cargo.lock, bundled
   SQLite amalgamation/source ID, workflow and produced artifact digest; and
5. an immutable artifact attestation whose subject is the upload-artifact digest, not
   merely an individual file inside the archive.

The current catalog intentionally leaves advisory, SBOM, immutable CI and attestation
locations pending. Absence of a locally installed advisory scanner is not a passing
scan. A new advisory after evidence capture invalidates the release decision until it
is triaged and the immutable evidence is regenerated.

## Clean-root scope and retention

The backup contains only the Feature 004 coordinator root and recovery-provider
inventory/packages. Restore requires new dedicated approved roots, detached signed
provenance and matching independently durable `RESTORE_PENDING` metadata. It keeps the
supervisor paused, rotates boot/instance/fencing authority, terminally reconciles old
nonterminal preparations and exports no activation capability.

This is subsystem clean-root evidence, not full clean-machine restore. Replay,
supervisor, policy, catalogue, secrets, workload runtime and effect adapters are outside
the artifact. A later activation feature must establish new authority and a newly
authorized signed plan plus replay claim.

V1 performs no automatic pruning. Canonical plans and recovery material retain their
source classification. Failed/released/delivered/quarantine/retirement records are
permanent tombstones; material retirement requires the guarded operation-bound or true
orphan protocol. No secure-erasure claim is made.

## Evidence still pending

- a green unchanged Linux x64, macOS arm64 and Windows x64 immutable matrix with
  retained artifacts and attestations;
- immutable CI preservation, digest binding and attestation of the locally passing
  explicit-session process-kill matrix for every frozen boundary;
- immutable preservation, uploaded-artifact binding and attestation of the retained clean-source
  physical Mac mini M4 latency and separate recovery-transfer artifacts;
- an approved at-rest profile; FileVault is currently only a local observation;
- production recovery-provider durability/corruption/clean-restore qualification;
- power-loss, sector-loss, directory-fsync and secure-erasure evidence;
- an exact-lockfile SBOM, license archive and retained RustSec scan with database and
  scanner identity;
- complete full-machine restore and any activation/dispatch evidence; and
- a reviewed removal drill proving PLAN-001 bytes, PLAN-002 semantics, PLAN-003 rows and
  the legacy MVP-0 path remain unchanged.

## Rollback and removal rule

Rollback never opens a newer/unknown schema or converts `RESTORE_PENDING` to `ACTIVE`.
Removal is source-level and non-destructive: remove the PLAN-004 crates, catalog entry,
workflow and fixtures only after running the documented cross-crate removal gates. Do
not rewrite, downgrade or reuse an existing coordinator/recovery root. Retained evidence
remains historical and must not be relabelled as evidence for another commit.
