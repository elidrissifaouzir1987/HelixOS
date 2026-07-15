---
type: "query"
date: "2026-07-14T09:37:57.255787+00:00"
question: "What did PLAN-005 T089 establish for immutable multi-platform CI?"
contributor: "graphify"
outcome: "useful"
---

# Q: What did PLAN-005 T089 establish for immutable multi-platform CI?

## Answer

T089 added a pinned GitHub Actions workflow for Ubuntu 24.04 x64, macOS 26 arm64, and Windows 2022 x64. Each host runs the same PowerShell prerequisite, conformance, E2E, fault-matrix, overload, migration, restore, corruption, and retention gates. Release evidence is built outside the checkout, removal is checked with external Cargo output, the manifest is refreshed, exact verification is required, and four current-run artifact attestations cover Linux, macOS, Windows, and the release bundle. Hosted CI explicitly excludes device effects, M4, power-loss, production-supervisor, full-machine-restore, and Tier-1 claims. Validation passed 55 evidence tests, actionlint, YAML parsing, whitespace checks, and immutable workflow SHA-256 df8ae870c824f5d1ca00256654546017cf47f7de737c928a9e9ff9d9da4a1ef8.

## Outcome

- Signal: useful