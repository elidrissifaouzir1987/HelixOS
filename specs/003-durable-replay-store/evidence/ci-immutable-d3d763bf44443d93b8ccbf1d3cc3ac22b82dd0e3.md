# PLAN-003 immutable three-host CI evidence

**Recorded**: 2026-07-10

**Commit**: `d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3`

**Workflow run**: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798`

**Event / attempt**: `push` / `1`

**Result**: Linux x64, macOS arm64 and Windows x64 all passed unchanged

The run executed `.github/workflows/durable-replay-store.yml` from the commit above.
Each job passed formatting, strict default and fault-surface Clippy, prerequisite
contracts, default replay tests, all 68 corpus/private-fault scenarios, release
contention, release process-kill recovery, runtime-profile verification, artifact upload
and provenance attestation.

## Shared reviewed inputs

- cases SHA-256:
  `7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff`
- expected outcomes SHA-256:
  `687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac`
- replay-store schema SHA-256:
  `7749bd426803f589c6a4dd0643d0b19d76aa38bc0645bc74db205f24e687d53d`
- backup-manifest schema SHA-256:
  `ecd2a0ddfbd0fc3e64f9a9bd2ea7659adef04bfd551c7c49bf3fceb51f3255b6`
- SQLite link profile: `rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static`
- SQLite version: `3.53.2`
- SQLite source ID:
  `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`
- verified runtime profile:
  `journal_mode:WAL,synchronous:FULL,wal_autocheckpoint_pages:0,foreign_keys:ON,trusted_schema:OFF,cell_size_check:ON`

## Linux x64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/job/86449052588`
- runner: `ubuntu-24.04`; image `ubuntu24` version `20260705.232.1`
- OS / architecture: `Ubuntu 24.04.4 LTS` / `X64`
- rustc: `1.96.1`; host `x86_64-unknown-linux-gnu`
- artifact: `plan-003-linux-x86_64-d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/artifacts/8237784700`
- uploaded ZIP SHA-256:
  `e764e6470f5a6c7a292fc366a10c25aafffc51178c147da5fdbb24b4697dc6e1`
- runtime metadata SHA-256:
  `84e471d1014736ecd9f47bf54297d0de7c5fef77b67fd98f95bb3eac333d964f`
- Cargo feature tree SHA-256:
  `62be312d3ce80ce0ec59a4916e4375b675b0181d0df1196b90c62f02c6f92c8f`
- rustc descriptor SHA-256:
  `2af3376cb254e69564e00978cada767f05432a299af78300c47d14c103366c1e`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34810403`

## macOS arm64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/job/86449052647`
- runner: `macos-26`; image `macos26` version `20260630.0213.1`
- OS / architecture: `macOS 26.4.0` / `ARM64`
- rustc: `1.96.1`; host `aarch64-apple-darwin`
- artifact: `plan-003-macos-arm64-d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/artifacts/8237830169`
- uploaded ZIP SHA-256:
  `45bbc565b257b878c62a85c561522a88fcea67f2bd36ac3331204de89ab0e694`
- runtime metadata SHA-256:
  `2931564f5734f8f5b29b5b2f5992ea8df4d4985cf15a96c97c07b2ba61663d4f`
- Cargo feature tree SHA-256:
  `988185961ff34f094cb248d732340a8f62d2646d5bf56534f938ac19e8e79819`
- rustc descriptor SHA-256:
  `28a3d6b44fd36649efdcc159a47e2e08cce8cd2dee204a8a0967125c7bb17b2d`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34810674`

## Windows x64

- job: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/job/86449052629`
- runner: `windows-2022`; image `win22` version `20260706.237.1`
- OS / architecture: `Microsoft Windows 10.0.20348` / `X64`
- rustc: `1.96.1`; host `x86_64-pc-windows-msvc`
- artifact: `plan-003-windows-x64-d3d763bf44443d93b8ccbf1d3cc3ac22b82dd0e3`
- artifact URL: `https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29118903798/artifacts/8237862796`
- uploaded ZIP SHA-256:
  `94a45b9c63fce6e28c247909d2a5048e584cf7ab134817e10b62b02c9c16e11d`
- runtime metadata SHA-256:
  `18f0fd7326523baeffa12196332f8dd08d4f1300d0082aa618bea8a157142fb4`
- Cargo feature tree SHA-256:
  `cf3d66d3d3f58495b38a3256be8cae9b29c053fd3fc3f6bdfc4b1fba1ed96ed5`
- rustc descriptor SHA-256:
  `8b46146bc1600536a6513c4826e8569fa2a5bd8cdb67b1b5a71c81b64d01f39a`
- attestation: `https://github.com/elidrissifaouzir1987/HelixOS/attestations/34810893`

The three downloaded ZIP digests were independently recomputed and matched GitHub's
uploaded-artifact digests. GitHub retains the artifacts for 90 days, until
2026-10-08. The attestations are repository build-provenance attestations signed through
the public-good Sigstore instance and uploaded to the Rekor transparency log.

## Evidence boundary

This is process-kill and hosted-runner evidence. The hosted arm64 macOS job is not the
physical Mac mini M4 probe, does not establish `F_FULLFSYNC`, and does not constitute
power-loss evidence. Those boundaries remain explicitly pending in T055.
