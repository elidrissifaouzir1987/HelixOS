---
type: "query"
date: "2026-07-13T10:21:14.787337+00:00"
question: "Prépare sans edit un plan concret T055 pour dispatch_end_to_end_contention.rs: vrai coordinator V2 préparé, vraie orchestration dispatch, livraison exacte au store adapter, commit du reçu via T052 et matrice SC-001."
contributor: "graphify"
outcome: "useful"
source_nodes: ["kernel/helix-coordinator-sqlite/src/prepare.rs", "SqliteCoordinatorStoreV2", "dispatch_prepared_once_v1", "receive_and_consume_exact_grant_v1", "CoordinatorReceiptLookupV1", "PendingDispatchOutboxV1", "SynchronizedProcessProbeV1"]
---

# Q: Prépare sans edit un plan concret T055 pour dispatch_end_to_end_contention.rs: vrai coordinator V2 préparé, vraie orchestration dispatch, livraison exacte au store adapter, commit du reçu via T052 et matrice SC-001.

## Answer

Expanded from original query via vocab: [dispatch, coordinator, preparation, grant, delivery, inbox, adapter, receipt, commit, contention, process, restart]. Le chemin réel combine la préparation PLAN-004, SqliteCoordinatorStoreV2, dispatch_prepared_once_v1, receive_and_consume_exact_grant_v1 puis commit_execution_receipt_v1. Les lacunes structurantes sont l absence d API publique pour extraire le grant exact de l outbox et marquer HANDED_OFF, ainsi que l implémentation adapter de DispatchInboxConsumerV1/readback. SC-001 doit être non ignoré: 10000 séquentiels, 100x64 threads et 20x8 processus, avec une consommation par opération, reçus PriorExact, checkpoints de réouverture et zéro effet.

## Outcome

- Signal: useful

## Source Nodes

- kernel/helix-coordinator-sqlite/src/prepare.rs
- SqliteCoordinatorStoreV2
- dispatch_prepared_once_v1
- receive_and_consume_exact_grant_v1
- CoordinatorReceiptLookupV1
- PendingDispatchOutboxV1
- SynchronizedProcessProbeV1