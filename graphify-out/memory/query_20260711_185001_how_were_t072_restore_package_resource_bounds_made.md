---
type: "implementation"
date: "2026-07-11T18:50:01.299457+00:00"
question: "How were T072 restore-package resource bounds made producer/consumer safe?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["root_safety.rs", "maintenance.rs", "RestorePackageCustodyV1", "ProvisionedBackupDestinationV1"]
---

# Q: How were T072 restore-package resource bounds made producer/consumer safe?

## Answer

root_safety now refuses directory enumeration incrementally at the remaining directory/file caps, retains full package-wide digest passes only at authority boundaries, and validates individual reads/hashes/copies through captured handles, ancestor identities, and captured digests. Backup preflights the restore-side worst-case directory/file shape, caps every provider/canonical/coordinator member at 64 MiB, accounts a 256 MiB worst-case package including retained staging hard links before publication, and checks restore deadlines after bounded traversals. Exact cap/cap+1 unit tests plus lib 116/116 and production backup/restore conformance passed.

## Outcome

- Signal: useful

## Source Nodes

- root_safety.rs
- maintenance.rs
- RestorePackageCustodyV1
- ProvisionedBackupDestinationV1