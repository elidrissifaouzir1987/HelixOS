---
type: "implementation-result"
date: "2026-07-11T21:57:50.875015+00:00"
question: "How was the final T072 backup resource-cap preflight corrected?"
contributor: "graphify"
outcome: "corrected"
correction: "Do not treat the 256 MiB aggregate as available entirely to provider material; reserve the database and mandatory manifest paths before writing."
source_nodes: ["maintenance.rs", "validate_backup_package_resource_shape_v1", "projected_backup_sqlite_length_v1"]
---

# Q: How was the final T072 backup resource-cap preflight corrected?

## Answer

The backup now projects the SQLite image as PRAGMA page_count multiplied by page_size before any online-backup write, adds mandatory canonical staging/published members and provider manifests to the aggregate lower bound, refuses four maximum-size materials before destination mutation, and verifies the produced SQLite length matches the projection. Exact-cap, cap-plus-one, zero-mutation, 120 unit, backup/restore, production restore and portability tests pass.

## Outcome

- Signal: corrected
- Correction: Do not treat the 256 MiB aggregate as available entirely to provider material; reserve the database and mandatory manifest paths before writing.

## Source Nodes

- maintenance.rs
- validate_backup_package_resource_shape_v1
- projected_backup_sqlite_length_v1