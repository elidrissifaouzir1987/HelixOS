# PLAN-004 evidence and supply-chain policy

This directory retains redacted evidence for Feature 004. Unless an artifact is listed
with an immutable commit, digest, platform and preservation URL in
`conformance/catalog.yaml`, its status is **pending evidence**. Local synthetic tests do
not establish production compensability, power-loss durability, restored-system
activation, physical-M4 performance or Tier 1 readiness.

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
- the real explicit-session process-kill matrix for every frozen boundary (registry-only
  iteration is not accepted as crash evidence);
- physical Mac mini M4 coordinator latency evidence and a separate recovery-transfer
  artifact;
- production recovery-provider durability/corruption/clean-restore qualification;
- power-loss, sector-loss, directory-fsync and secure-erasure evidence;
- complete full-machine restore and any activation/dispatch evidence; and
- a reviewed removal drill proving PLAN-001 bytes, PLAN-002 semantics, PLAN-003 rows and
  the legacy MVP-0 path remain unchanged.

## Rollback and removal rule

Rollback never opens a newer/unknown schema or converts `RESTORE_PENDING` to `ACTIVE`.
Removal is source-level and non-destructive: remove the PLAN-004 crates, catalog entry,
workflow and fixtures only after running the documented cross-crate removal gates. Do
not rewrite, downgrade or reuse an existing coordinator/recovery root. Retained evidence
remains historical and must not be relabelled as evidence for another commit.
