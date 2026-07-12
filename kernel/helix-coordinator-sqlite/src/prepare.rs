//! Private atomic preparation transaction boundary.

#![allow(dead_code)] // The portable store adapter is wired by T037.

pub(crate) mod production {
    #[cfg(not(test))]
    use crate::budget::{checked_budget_reservation_v1, BudgetVectorCheckErrorV1};
    use crate::comparison_digest::immutable_comparison_digest_for_operation_v1;
    use crate::outbox::{stage_prepared_event_v1, PreparedEventRowV1};
    use helix_contracts::{AtomicityV1, RecoveryClassV1, RiskLevelV1, Sha256Digest, MAX_SAFE_U64};
    use helix_coordinator_sqlite::CoordinatorFaultProbeV1;
    use helix_plan_preparation::{
        recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
        recovery_target_reference_digest_v1, BudgetReservationReceiptInputV1,
        BudgetReservationReceiptV1, BudgetReservationStateV1, FinalCommitGateV1,
        FinalCommitInFlightV1, FinalCommitPermitOutcomeV1, FinalCommitPermitRequestInputV1,
        FinalCommitPermitRequestV1, FinalCommitPermitV1, FinalCommitReadbackResolutionV1,
        FinalCommitResolutionV1, FinalCommitStoreClassificationV1, PreparationCapturePhaseV1,
        PreparationCommitInputV1, PreparationCommitReceiptInputV1, PreparationCommitReceiptV1,
        PreparationCommitUncertainV1, RecoveryEvidenceClassV1, RecoveryEvidenceV1,
        RecoveryMaterialStateV1, PREPARATION_BUDGET_CONTRACT_VERSION_V1,
        PREPARATION_CONTEXT_VERSION_V1, PREPARATION_STORE_CONTRACT_VERSION_V1,
        RECOVERY_PROVIDER_CONTRACT_VERSION_V1, RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
    };
    use rusqlite::{
        named_params, params, Connection, ErrorCode, OptionalExtension, Transaction,
        TransactionBehavior,
    };
    use std::fmt;

    // Several historical integration fixtures source-include this file without the
    // crate-private `budget` module. Production always uses the coordinator T044 helper;
    // test builds retain the identical arithmetic order through the portable T044 vector.
    #[cfg(test)]
    use source_included_budget_v1::{checked_budget_reservation_v1, BudgetVectorCheckErrorV1};

    #[cfg(test)]
    mod source_included_budget_v1 {
        use helix_plan_preparation::{BudgetVectorInputV1, BudgetVectorV1};

        pub(super) enum BudgetVectorCheckErrorV1 {
            ArithmeticInvalid,
            Exhausted,
        }

        pub(super) fn checked_budget_reservation_v1(
            total: [u64; 4],
            held: [u64; 4],
            requested: [u64; 4],
        ) -> Result<[u64; 4], BudgetVectorCheckErrorV1> {
            let total = vector_v1(total)?;
            let held = vector_v1(held)?;
            let requested = vector_v1(requested)?;
            let remaining = total
                .checked_subtract_v1(&held)
                .map_err(|_| BudgetVectorCheckErrorV1::ArithmeticInvalid)?;
            let next = held
                .checked_add_v1(&requested)
                .map_err(|_| BudgetVectorCheckErrorV1::ArithmeticInvalid)?;
            let remaining = components_v1(&remaining);
            let requested_components = components_v1(&requested);
            if (0..4).any(|index| requested_components[index] > remaining[index]) {
                return Err(BudgetVectorCheckErrorV1::Exhausted);
            }
            Ok(components_v1(&next))
        }

        fn vector_v1(values: [u64; 4]) -> Result<BudgetVectorV1, BudgetVectorCheckErrorV1> {
            BudgetVectorV1::try_new(BudgetVectorInputV1 {
                max_cost_micro_units: values[0],
                action_limit: values[1],
                egress_bytes_limit: values[2],
                recovery_bytes: values[3],
            })
            .map_err(|_| BudgetVectorCheckErrorV1::ArithmeticInvalid)
        }

        fn components_v1(vector: &BudgetVectorV1) -> [u64; 4] {
            [
                vector.max_cost_micro_units(),
                vector.action_limit(),
                vector.egress_bytes_limit(),
                vector.recovery_bytes(),
            ]
        }
    }

    const APPLICATION_ID_V1: i64 = 1_212_962_883;
    const SCHEMA_VERSION_V1: i64 = 1;
    const CANONICAL_MEMBER_COUNT_V1: usize = 8;

    /// Storage-only bindings not derivable from the portable commit input.
    ///
    /// The digest domains are deliberately supplied by trusted adapter wiring. T034 does
    /// not invent encodings for the target reference, precondition identity, or boot
    /// binding, whose v1 domains remain outside the reviewed SQL contract.
    pub(crate) struct CoordinatorCommitBindingsV1<'borrow, 'input> {
        pub(crate) commit: &'borrow PreparationCommitInputV1<'input>,
        pub(crate) event_id: Sha256Digest,
        pub(crate) target_reference_digest: Sha256Digest,
        pub(crate) precondition_identity_digest: Sha256Digest,
        pub(crate) boot_binding_digest: Sha256Digest,
        pub(crate) caller_deadline_monotonic_ms: u64,
    }

    impl fmt::Debug for CoordinatorCommitBindingsV1<'_, '_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CoordinatorCommitBindingsV1")
                .finish_non_exhaustive()
        }
    }

    /// Custody retained only for the one explicitly uncertain readback window.
    pub(crate) struct CoordinatorCommitUncertainV1<I> {
        pub(crate) portable: PreparationCommitUncertainV1,
        pub(crate) in_flight: I,
        pub(crate) custody: CoordinatorUncertainCommitCustodyV1,
    }

    impl<I> fmt::Debug for CoordinatorCommitUncertainV1<I> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CoordinatorCommitUncertainV1")
                .finish_non_exhaustive()
        }
    }

    /// Exact restricted transaction keys retained for T035/T037 readback registration.
    ///
    /// This is neither a positive receipt nor a public status token. Its diagnostics are
    /// redacted and it remains inside the coordinator adapter keyed by the attempt.
    pub(crate) struct CoordinatorUncertainCommitCustodyV1 {
        pub(crate) operation_id: String,
        pub(crate) attempt_id: Sha256Digest,
        pub(crate) plan_id: Sha256Digest,
        pub(crate) reservation_id: String,
        pub(crate) event_id: Sha256Digest,
        pub(crate) scope_id: Sha256Digest,
        pub(crate) budget_scope_binding_digest: Sha256Digest,
        pub(crate) comparison_digest: Sha256Digest,
        pub(crate) replay_claim_id: Sha256Digest,
        pub(crate) replay_claimant_generation: u64,
        pub(crate) replay_binding_digest: Sha256Digest,
        pub(crate) target_reference_digest: Sha256Digest,
        pub(crate) precondition_identity_digest: Sha256Digest,
        pub(crate) boot_binding_digest: Sha256Digest,
        pub(crate) budget_scope_generation: u64,
        pub(crate) store_generation: u64,
        pub(crate) operation_generation: u64,
        pub(crate) event_generation: u64,
        pub(crate) reservation_created_generation: u64,
        pub(crate) supervisor_generation: u64,
        pub(crate) instance_epoch: u64,
        pub(crate) fencing_epoch: u64,
    }

    impl fmt::Debug for CoordinatorUncertainCommitCustodyV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CoordinatorUncertainCommitCustodyV1")
                .finish_non_exhaustive()
        }
    }

    /// Closed adapter classification for one full-store verification pass.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum CoordinatorCommitVerificationErrorV1 {
        Unavailable,
        Busy,
        Unhealthy,
    }

    /// Closed result of the production-internal SQLite transaction primitive.
    // Keep exact uncertain custody inline: allocating after possible commit would add
    // an avoidable failure boundary precisely where classification must be closed.
    #[allow(clippy::large_enum_variant)]
    pub(crate) enum CoordinatorCommitOutcomeV1<I> {
        Committed(PreparationCommitReceiptV1),
        ConfirmedRollback,
        Uncertain(CoordinatorCommitUncertainV1<I>),
        Unclassified,
        PermitRevoked,
        PermitUnavailable,
        PermitDeadlineReached,
        PermitUnsupported,
        StoreUnavailable,
        StoreBusy,
        StoreUnhealthy,
        OperationConflict,
        AlreadyPrepared,
        Conflict,
        BudgetScopeMissing,
        BudgetBindingConflict,
        BudgetArithmeticInvalid,
        BudgetExhausted,
    }

    impl<I> fmt::Debug for CoordinatorCommitOutcomeV1<I> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let variant = match self {
                Self::Committed(_) => "Committed(..)",
                Self::ConfirmedRollback => "ConfirmedRollback",
                Self::Uncertain(_) => "Uncertain(..)",
                Self::Unclassified => "Unclassified",
                Self::PermitRevoked => "PermitRevoked",
                Self::PermitUnavailable => "PermitUnavailable",
                Self::PermitDeadlineReached => "PermitDeadlineReached",
                Self::PermitUnsupported => "PermitUnsupported",
                Self::StoreUnavailable => "StoreUnavailable",
                Self::StoreBusy => "StoreBusy",
                Self::StoreUnhealthy => "StoreUnhealthy",
                Self::OperationConflict => "OperationConflict",
                Self::AlreadyPrepared => "AlreadyPrepared",
                Self::Conflict => "Conflict",
                Self::BudgetScopeMissing => "BudgetScopeMissing",
                Self::BudgetBindingConflict => "BudgetBindingConflict",
                Self::BudgetArithmeticInvalid => "BudgetArithmeticInvalid",
                Self::BudgetExhausted => "BudgetExhausted",
            };
            write!(formatter, "CoordinatorCommitOutcomeV1::{variant}")
        }
    }

    #[derive(Clone, Copy)]
    struct GenerationsV1 {
        store: u64,
        operation: u64,
        budget: u64,
        event: u64,
    }

    struct ScopeV1 {
        id: [u8; 32],
        held: [u64; 4],
        next_held: [u64; 4],
    }

    enum StagingErrorV1 {
        StoreUnavailable,
        StoreBusy,
        StoreUnhealthy,
        OperationConflict,
        AlreadyPrepared,
        Conflict,
        BudgetScopeMissing,
        BudgetBindingConflict,
        BudgetArithmeticInvalid,
        BudgetExhausted,
    }

    struct StagedCommitV1<'connection> {
        transaction: Transaction<'connection>,
        receipt: PreparationCommitReceiptV1,
        uncertain_custody: CoordinatorUncertainCommitCustodyV1,
    }

    /// Stages and commits one canonical positive coordinator transaction.
    ///
    /// The connection must come from the already attested/configured store path. This
    /// function rechecks the connection profile and lightweight database health, acquires
    /// `BEGIN IMMEDIATE`, repeats operation and budget serialization checks, and leaves the
    /// transaction open until the supervisor permit consumes the one actual `COMMIT` call.
    pub(crate) fn commit_preparing_transaction_v1<G, N, V>(
        connection: &mut Connection,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        gate: &mut G,
        fault_probe: &CoordinatorFaultProbeV1,
        mut permit_clock: N,
        mut verify_full_connection: V,
    ) -> CoordinatorCommitOutcomeV1<
        <<G as FinalCommitGateV1>::Permit as FinalCommitPermitV1>::InFlight,
    >
    where
        G: FinalCommitGateV1,
        N: FnMut() -> Result<u64, ()>,
        V: FnMut(&Connection) -> Result<(), CoordinatorCommitVerificationErrorV1>,
    {
        if validate_commit_input_v1(bindings).is_err() {
            return CoordinatorCommitOutcomeV1::StoreUnhealthy;
        }

        let staged = match begin_and_stage_v1(
            connection,
            bindings,
            fault_probe,
            &mut verify_full_connection,
        ) {
            Ok(staged) => staged,
            Err(error) => return map_staging_error_v1(error),
        };
        let permit_entry_monotonic_ms = match permit_clock() {
            Ok(now) if now < bindings.caller_deadline_monotonic_ms => now,
            _ => {
                return if staged.transaction.rollback().is_ok() {
                    CoordinatorCommitOutcomeV1::PermitDeadlineReached
                } else {
                    CoordinatorCommitOutcomeV1::Unclassified
                };
            }
        };
        let request = match FinalCommitPermitRequestV1::try_new(FinalCommitPermitRequestInputV1 {
            attempt: bindings.commit.attempt(),
            expected_supervisor_generation: bindings.commit.final_context().supervisor_generation(),
            caller_deadline_monotonic_ms: bindings.caller_deadline_monotonic_ms,
            permit_entry_monotonic_ms,
        }) {
            Ok(request) => request,
            Err(_) => {
                return if staged.transaction.rollback().is_ok() {
                    CoordinatorCommitOutcomeV1::StoreUnhealthy
                } else {
                    CoordinatorCommitOutcomeV1::Unclassified
                };
            }
        };

        let permit = match gate.enter_commit_permit_instrumented_v1(&request) {
            FinalCommitPermitOutcomeV1::Permitted(permit) => permit,
            FinalCommitPermitOutcomeV1::Revoked => {
                return rollback_for_gate_refusal_v1(
                    staged.transaction,
                    CoordinatorCommitOutcomeV1::PermitRevoked,
                );
            }
            FinalCommitPermitOutcomeV1::Unavailable => {
                return rollback_for_gate_refusal_v1(
                    staged.transaction,
                    CoordinatorCommitOutcomeV1::PermitUnavailable,
                );
            }
            FinalCommitPermitOutcomeV1::DeadlineReached => {
                return rollback_for_gate_refusal_v1(
                    staged.transaction,
                    CoordinatorCommitOutcomeV1::PermitDeadlineReached,
                );
            }
            FinalCommitPermitOutcomeV1::Unsupported => {
                return rollback_for_gate_refusal_v1(
                    staged.transaction,
                    CoordinatorCommitOutcomeV1::PermitUnsupported,
                );
            }
        };

        // Keep the transaction in an Option so a permit that aborts before invoking the
        // closure can still receive an explicit SQLite rollback. If COMMIT is invoked, the
        // transaction is consumed exactly once and any SQLite error is conservatively
        // classified as uncertain.
        let mut transaction = Some(staged.transaction);
        let resolution = commit_sqlite_once_with_permit_v1(permit, &mut transaction, fault_probe);

        match resolution {
            FinalCommitResolutionV1::Committed if transaction.is_none() => {
                CoordinatorCommitOutcomeV1::Committed(staged.receipt)
            }
            FinalCommitResolutionV1::Committed => rollback_unclassified_v1(transaction),
            FinalCommitResolutionV1::Aborted => {
                if let Some(transaction) = transaction {
                    if transaction.rollback().is_ok() {
                        CoordinatorCommitOutcomeV1::ConfirmedRollback
                    } else {
                        CoordinatorCommitOutcomeV1::Unclassified
                    }
                } else {
                    CoordinatorCommitOutcomeV1::Unclassified
                }
            }
            FinalCommitResolutionV1::Uncertain(in_flight) if transaction.is_none() => {
                match PreparationCommitUncertainV1::try_new(
                    PREPARATION_STORE_CONTRACT_VERSION_V1,
                    bindings.commit.attempt().digest(),
                ) {
                    Ok(portable) => {
                        CoordinatorCommitOutcomeV1::Uncertain(CoordinatorCommitUncertainV1 {
                            portable,
                            in_flight,
                            custody: staged.uncertain_custody,
                        })
                    }
                    Err(_) => {
                        let _ = in_flight.resolve_readback_instrumented_v1(
                            FinalCommitReadbackResolutionV1::Inconclusive,
                        );
                        CoordinatorCommitOutcomeV1::Unclassified
                    }
                }
            }
            FinalCommitResolutionV1::Uncertain(in_flight) => {
                let result = rollback_unclassified_v1(transaction);
                let _ = in_flight.resolve_readback_instrumented_v1(
                    FinalCommitReadbackResolutionV1::Inconclusive,
                );
                result
            }
            FinalCommitResolutionV1::Ambiguous => rollback_unclassified_v1(transaction),
        }
    }

    fn commit_sqlite_once_with_permit_v1<P>(
        permit: P,
        transaction: &mut Option<Transaction<'_>>,
        fault_probe: &CoordinatorFaultProbeV1,
    ) -> FinalCommitResolutionV1<P::InFlight>
    where
        P: FinalCommitPermitV1,
    {
        permit.commit_once_instrumented_v1(|| {
            let transaction = match transaction.take() {
                Some(transaction) => transaction,
                None => return FinalCommitStoreClassificationV1::Unclassified,
            };
            reach_sqlite_commit_invoked_v1(fault_probe);
            let classification = match transaction.commit() {
                Ok(()) => FinalCommitStoreClassificationV1::Committed,
                Err(_) => FinalCommitStoreClassificationV1::Uncertain,
            };
            reach_sqlite_commit_returned_v1(fault_probe);
            classification
        })
    }

    fn begin_and_stage_v1<'connection, V>(
        connection: &'connection mut Connection,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        fault_probe: &CoordinatorFaultProbeV1,
        verify_full_connection: &mut V,
    ) -> Result<StagedCommitV1<'connection>, StagingErrorV1>
    where
        V: FnMut(&Connection) -> Result<(), CoordinatorCommitVerificationErrorV1>,
    {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_begin_error_v1)?;
        reach_begin_immediate_acquired_v1(fault_probe);

        if let Err(error) =
            verify_commit_connection_v1(&transaction, verify_full_connection, fault_probe)
        {
            return rollback_staging_error_v1(transaction, error);
        }

        let staged = stage_all_members_v1(&transaction, bindings, fault_probe);
        match staged {
            Ok((generations, scope)) => {
                let comparison_digest = match finalize_production_comparison_digest_v1(
                    &transaction,
                    bindings.commit.final_context().operation_id(),
                ) {
                    Ok(digest) => digest,
                    Err(()) => {
                        return rollback_staging_error_v1(
                            transaction,
                            StagingErrorV1::StoreUnhealthy,
                        );
                    }
                };
                // The comparison member is complete only after all joined rows exist and
                // its shared digest has replaced the transaction-local placeholder.
                reach_production_member_staged_v1(fault_probe);
                if verify_staged_foreign_keys_v1(&transaction).is_err() {
                    return rollback_staging_error_v1(transaction, StagingErrorV1::StoreUnhealthy);
                }
                if let Err(error) =
                    verify_injected_full_snapshot_v1(&transaction, verify_full_connection)
                {
                    return rollback_staging_error_v1(transaction, error);
                }
                let receipt = match build_commit_receipt_v1(bindings, generations) {
                    Ok(receipt) => receipt,
                    Err(error) => return rollback_staging_error_v1(transaction, error),
                };
                let uncertain_custody =
                    build_uncertain_custody_v1(bindings, generations, &scope, comparison_digest);
                Ok(StagedCommitV1 {
                    transaction,
                    receipt,
                    uncertain_custody,
                })
            }
            Err(error) => rollback_staging_error_v1(transaction, error),
        }
    }

    fn stage_all_members_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        fault_probe: &CoordinatorFaultProbeV1,
    ) -> Result<(GenerationsV1, ScopeV1), StagingErrorV1> {
        classify_operation_identity_v1(transaction, bindings)?;
        reach_operation_identity_classified_v1(fault_probe);
        let scope = load_and_classify_scope_v1(transaction, bindings)?;
        reach_budget_scope_loaded_v1(fault_probe);
        reach_final_arithmetic_capacity_classified_v1(fault_probe);
        classify_residual_unique_keys_v1(transaction, bindings)?;
        let generations = allocate_generations_v1(transaction)?;

        stage_metadata_v1(transaction, generations)?;
        reach_production_member_staged_v1(fault_probe);
        stage_operation_v1(transaction, bindings, generations)?;
        reach_production_member_staged_v1(fault_probe);
        stage_transition_v1(transaction, bindings, generations)?;
        reach_production_member_staged_v1(fault_probe);
        stage_comparison_v1(transaction, bindings, &scope)?;
        stage_scope_delta_v1(transaction, bindings, &scope)?;
        reach_production_member_staged_v1(fault_probe);
        stage_reservation_v1(transaction, bindings, &scope, generations)?;
        reach_production_member_staged_v1(fault_probe);
        stage_recovery_v1(transaction, bindings)?;
        reach_production_member_staged_v1(fault_probe);
        stage_prepared_event_v1(
            transaction,
            PreparedEventRowV1 {
                event_id: bindings.event_id.as_bytes(),
                event_generation: to_i64_v1(generations.event)?,
                operation_id: bindings.commit.final_context().operation_id(),
                operation_state_generation: to_i64_v1(generations.operation)?,
            },
        )
        .map_err(map_mutation_error_v1)?;
        reach_production_member_staged_v1(fault_probe);
        Ok((generations, scope))
    }

    fn validate_commit_input_v1(bindings: &CoordinatorCommitBindingsV1<'_, '_>) -> Result<(), ()> {
        let input = bindings.commit;
        let eligible = input.eligible();
        let context = input.final_context();
        let claims = eligible.authentic().preparation_claims();
        let eligibility = eligible.authentic().eligibility_claims();
        let requested = input.requested_budget();
        let context_requested = context.requested_budget();
        let preflight = input.preflight();
        let expected_requested = [
            claims.budget().max_cost_micro_units(),
            claims.budget().action_limit(),
            claims.budget().egress_bytes_limit(),
            claims.recovery_reserved_bytes(),
        ];
        let actual_requested = [
            requested.max_cost_micro_units(),
            requested.action_limit(),
            requested.egress_bytes_limit(),
            requested.recovery_bytes(),
        ];
        let observed_remaining = preflight.observed_remaining();
        let remaining = [
            observed_remaining.max_cost_micro_units(),
            observed_remaining.action_limit(),
            observed_remaining.egress_bytes_limit(),
            observed_remaining.recovery_bytes(),
        ];
        let canonical_target_reference_digest =
            recovery_target_reference_digest_v1(claims.target()).map_err(|_| ())?;
        let canonical_precondition_identity_digest = recovery_precondition_identity_digest_v1(
            claims.precondition_volume_id(),
            claims.precondition_file_id(),
        )
        .map_err(|_| ())?;
        let canonical_boot_binding_digest = recovery_boot_binding_digest_v1(
            context.boot_id(),
            context.instance_epoch(),
            context.fencing_epoch(),
        )
        .map_err(|_| ())?;

        let scalar_bindings_match = input.contract_version()
            == PREPARATION_STORE_CONTRACT_VERSION_V1
            && context.context_version() == PREPARATION_CONTEXT_VERSION_V1
            && matches!(context.phase(), PreparationCapturePhaseV1::Final)
            && context.plan_id() == claims.plan_id()
            && context.operation_id() == claims.operation_id()
            && context.task_id() == claims.task_id()
            && context.workload_id() == claims.workload_id()
            && context.attempt_id() == input.attempt().digest()
            && context.boot_id() == eligibility.boot_id()
            && context.instance_epoch() == eligibility.instance_epoch()
            && context.fencing_epoch() == eligibility.fencing_epoch()
            && context.lease_digest() == claims.task_lease_digest()
            && context.currency_code() == claims.budget().currency_code()
            && context.price_table_id() == claims.budget().price_table_id()
            && context_requested.max_cost_micro_units() == actual_requested[0]
            && context_requested.action_limit() == actual_requested[1]
            && context_requested.egress_bytes_limit() == actual_requested[2]
            && context_requested.recovery_bytes() == actual_requested[3]
            && actual_requested == expected_requested
            && preflight.contract_version() == PREPARATION_STORE_CONTRACT_VERSION_V1
            && preflight.observed_scope_generation() == context.budget_scope_generation()
            && preflight.observed_scope_binding_digest() == context.budget_scope_binding_digest()
            && bindings.target_reference_digest == canonical_target_reference_digest
            && bindings.precondition_identity_digest == canonical_precondition_identity_digest
            && bindings.boot_binding_digest == canonical_boot_binding_digest
            && remaining
                .into_iter()
                .zip(actual_requested)
                .all(|(remaining, requested)| requested <= remaining)
            && bindings.caller_deadline_monotonic_ms <= context.effective_deadline_monotonic_ms()
            && bindings.caller_deadline_monotonic_ms <= MAX_SAFE_U64;
        if !scalar_bindings_match {
            return Err(());
        }

        match input.recovery_evidence() {
            RecoveryEvidenceV1::Material(receipt) => {
                let Some(provider) = context.recovery_provider() else {
                    return Err(());
                };
                let evidence_class = match receipt.evidence_class() {
                    RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
                    RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
                };
                if receipt.contract_version() != RECOVERY_RECEIPT_CONTRACT_VERSION_V1
                    || receipt.provider_profile_version() != RECOVERY_PROVIDER_CONTRACT_VERSION_V1
                    || receipt.plan_id() != claims.plan_id()
                    || receipt.operation_id() != claims.operation_id()
                    || receipt.attempt_id() != input.attempt().digest()
                    || receipt.target_reference_digest() != canonical_target_reference_digest
                    || receipt.precondition_identity_digest()
                        != canonical_precondition_identity_digest
                    || receipt.precondition_digest() != claims.precondition_content_sha256()
                    || receipt.precondition_length() != claims.precondition_byte_length()
                    || receipt.recovery_class() != RecoveryClassV1::Compensation
                    || claims.recovery_class() != RecoveryClassV1::Compensation
                    || receipt.atomicity() != claims.atomicity()
                    || receipt.material_digest() != receipt.precondition_digest()
                    || claims.preimage_sha256() != Some(receipt.material_digest())
                    || receipt.material_length() != receipt.precondition_length()
                    || receipt.reserved_capacity() != claims.recovery_reserved_bytes()
                    || receipt.reserved_capacity() < receipt.material_length()
                    || receipt.boot_binding_digest() != canonical_boot_binding_digest
                    || receipt.instance_epoch() != context.instance_epoch()
                    || receipt.fencing_epoch() != context.fencing_epoch()
                    || !matches!(receipt.state(), RecoveryMaterialStateV1::Published)
                    || provider.profile_id() != receipt.provider_profile_id()
                    || provider.profile_version() != receipt.provider_profile_version()
                    || provider.provider_id() != receipt.provider_id()
                    || provider.provider_generation() != receipt.provider_generation()
                    || provider.evidence_class() != evidence_class
                    || provider.at_rest_profile_id() != receipt.at_rest_profile_id()
                    || provider.capability_binding_digest() != receipt.capability_binding_digest()
                    || !provider.supports_create_only()
                    || !provider.supports_sync()
                    || !provider.supports_no_clobber_publication()
                {
                    return Err(());
                }
            }
            RecoveryEvidenceV1::Irreversible(evidence) => {
                if evidence.contract_version() != RECOVERY_RECEIPT_CONTRACT_VERSION_V1
                    || evidence.risk_level() != RiskLevelV1::L2
                    || eligibility.risk_level() != RiskLevelV1::L2
                    || evidence.recovery_class() != RecoveryClassV1::Irreversible
                    || claims.recovery_class() != RecoveryClassV1::Irreversible
                    || evidence.atomicity() != claims.atomicity()
                    || !evidence.no_material()
                    || claims.preimage_sha256().is_some()
                    || context.recovery_provider().is_some()
                {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    fn verify_commit_connection_v1<V>(
        connection: &Connection,
        verify_full_connection: &mut V,
        fault_probe: &CoordinatorFaultProbeV1,
    ) -> Result<(), StagingErrorV1>
    where
        V: FnMut(&Connection) -> Result<(), CoordinatorCommitVerificationErrorV1>,
    {
        // Trusted adapter wiring binds the exact provisioner-attested root identity,
        // reviewed schema, historical PLAN-001 keys, comparison digests, and every
        // cross-record invariant before the lightweight profile checks below.
        verify_injected_full_snapshot_v1(connection, verify_full_connection)?;
        let application_id = pragma_i64_v1(connection, "application_id")
            .map_err(|()| StagingErrorV1::StoreUnhealthy)?;
        let user_version = pragma_i64_v1(connection, "user_version")
            .map_err(|()| StagingErrorV1::StoreUnhealthy)?;
        let active_root: Option<Vec<u8>> = connection
            .query_row(
                "SELECT root_identity FROM coordinator_store_meta \
             WHERE singleton = 1 AND format_version = 1 \
               AND root_lifecycle_state = 'ACTIVE' \
               AND restore_identity_digest IS NULL \
               AND restore_attestation_digest IS NULL \
               AND restore_state_generation = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        if application_id != APPLICATION_ID_V1
            || user_version != SCHEMA_VERSION_V1
            || active_root
                .as_ref()
                .is_none_or(|identity| identity.len() != 32)
        {
            return Err(StagingErrorV1::StoreUnhealthy);
        }
        reach_root_accepted_v1(fault_probe);

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        let exact_profile = journal_mode.eq_ignore_ascii_case("wal")
            && pragma_i64_v1(connection, "synchronous")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 2
            && pragma_i64_v1(connection, "wal_autocheckpoint")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 0
            && pragma_i64_v1(connection, "foreign_keys")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 1
            && pragma_i64_v1(connection, "recursive_triggers")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 1
            && pragma_i64_v1(connection, "trusted_schema")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 0
            && pragma_i64_v1(connection, "cell_size_check")
                .map_err(|()| StagingErrorV1::StoreUnhealthy)?
                == 1;
        if !exact_profile {
            return Err(StagingErrorV1::StoreUnhealthy);
        }
        reach_profile_accepted_v1(fault_probe);

        reach_invariants_accepted_v1(fault_probe);
        Ok(())
    }

    fn verify_injected_full_snapshot_v1<V>(
        connection: &Connection,
        verify_full_connection: &mut V,
    ) -> Result<(), StagingErrorV1>
    where
        V: FnMut(&Connection) -> Result<(), CoordinatorCommitVerificationErrorV1>,
    {
        verify_full_connection(connection).map_err(map_verification_error_v1)
    }

    fn map_verification_error_v1(error: CoordinatorCommitVerificationErrorV1) -> StagingErrorV1 {
        match error {
            CoordinatorCommitVerificationErrorV1::Unavailable => StagingErrorV1::StoreUnavailable,
            CoordinatorCommitVerificationErrorV1::Busy => StagingErrorV1::StoreBusy,
            CoordinatorCommitVerificationErrorV1::Unhealthy => StagingErrorV1::StoreUnhealthy,
        }
    }

    struct ExistingOperationV1 {
        operation_id: String,
        attempt_id: Vec<u8>,
        plan_id: Vec<u8>,
        task_id: String,
        workload_id: String,
        reservation_id: String,
    }

    fn classify_operation_identity_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
    ) -> Result<(), StagingErrorV1> {
        let input = bindings.commit;
        let claims = input.eligible().authentic().preparation_claims();
        let mut statement = transaction
            .prepare(
                "SELECT operation_id, attempt_id, plan_id, task_id, workload_id, \
                    reservation_id FROM prepared_operations \
                 WHERE operation_id = ?1 OR attempt_id = ?2 OR plan_id = ?3 \
                 ORDER BY operation_id LIMIT 2",
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        let rows = statement
            .query_map(
                params![
                    claims.operation_id(),
                    input.attempt().as_bytes().as_slice(),
                    claims.plan_id().as_bytes().as_slice(),
                ],
                |row| {
                    Ok(ExistingOperationV1 {
                        operation_id: row.get(0)?,
                        attempt_id: row.get(1)?,
                        plan_id: row.get(2)?,
                        task_id: row.get(3)?,
                        workload_id: row.get(4)?,
                        reservation_id: row.get(5)?,
                    })
                },
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        let existing = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        if existing.is_empty() {
            return Ok(());
        }
        if existing.len() == 1 && is_exact_prior_operation_v1(&existing[0], bindings) {
            return Err(StagingErrorV1::AlreadyPrepared);
        }
        Err(StagingErrorV1::OperationConflict)
    }

    fn is_exact_prior_operation_v1(
        existing: &ExistingOperationV1,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
    ) -> bool {
        let input = bindings.commit;
        let claims = input.eligible().authentic().preparation_claims();
        existing.operation_id == claims.operation_id()
            && existing.attempt_id.as_slice() == input.attempt().as_bytes()
            && existing.plan_id.as_slice() == claims.plan_id().as_bytes()
            && existing.task_id == claims.task_id()
            && existing.workload_id == claims.workload_id()
            && existing.reservation_id == claims.budget().reservation_id()
    }

    fn load_and_classify_scope_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
    ) -> Result<ScopeV1, StagingErrorV1> {
        let input = bindings.commit;
        let context = input.final_context();
        let claims = input.eligible().authentic().preparation_claims();
        let lease_scope_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM budget_scopes WHERE task_lease_digest = ?1",
                [claims.task_lease_digest().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        if lease_scope_count == 0 {
            return Err(StagingErrorV1::BudgetScopeMissing);
        }
        if lease_scope_count != 1 {
            return Err(StagingErrorV1::BudgetBindingConflict);
        }
        let row = transaction
            .query_row(
                "SELECT scope_id, total_cost_micro_units, total_action_count, \
                    total_egress_bytes, total_recovery_bytes, held_cost_micro_units, \
                    held_action_count, held_egress_bytes, held_recovery_bytes \
             FROM budget_scopes \
             WHERE task_lease_digest = ?1 AND allowance_binding_digest = ?2 \
               AND scope_generation = ?3 AND currency_code = ?4 AND price_table_id = ?5",
                params![
                    claims.task_lease_digest().as_bytes().as_slice(),
                    context.budget_scope_binding_digest().as_bytes().as_slice(),
                    to_i64_v1(context.budget_scope_generation())?,
                    context.currency_code(),
                    context.price_table_id(),
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        [row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?],
                        [row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?],
                    ))
                },
            )
            .optional()
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?
            .ok_or(StagingErrorV1::BudgetBindingConflict)?;
        let id: [u8; 32] = row
            .0
            .try_into()
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        let reservation_occupied: bool = transaction
            .query_row(
                "SELECT EXISTS (\
                    SELECT 1 FROM budget_reservations WHERE reservation_id = ?1\
                 )",
                [claims.budget().reservation_id()],
                |row| row.get(0),
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        if reservation_occupied {
            return Err(StagingErrorV1::BudgetBindingConflict);
        }
        let mut total = [0_u64; 4];
        let mut held = [0_u64; 4];
        for index in 0..4 {
            total[index] = safe_i64_v1(row.1[index])?;
            held[index] = safe_i64_v1(row.2[index])?;
        }
        let next_held = checked_budget_reservation_v1(total, held, requested_vector_v1(input))
            .map_err(|error| match error {
                BudgetVectorCheckErrorV1::ArithmeticInvalid => {
                    StagingErrorV1::BudgetArithmeticInvalid
                }
                BudgetVectorCheckErrorV1::Exhausted => StagingErrorV1::BudgetExhausted,
            })?;
        Ok(ScopeV1 {
            id,
            held,
            next_held,
        })
    }

    /// Leaves row 42 for unique-key collisions outside operation and reservation identity.
    fn classify_residual_unique_keys_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
    ) -> Result<(), StagingErrorV1> {
        let occupied: bool = transaction
            .query_row(
                "SELECT EXISTS (\
                    SELECT 1 FROM prepared_operations WHERE current_event_id = ?1\
                 ) OR EXISTS (\
                    SELECT 1 FROM preparation_events WHERE event_id = ?1\
                 )",
                [bindings.event_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        if occupied {
            return Err(StagingErrorV1::Conflict);
        }
        Ok(())
    }

    fn allocate_generations_v1(
        transaction: &Transaction<'_>,
    ) -> Result<GenerationsV1, StagingErrorV1> {
        let current: (i64, i64, i64, i64) = transaction
            .query_row(
                "SELECT store_generation, operation_generation, budget_generation, \
                    event_generation FROM coordinator_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        let current_store = safe_i64_v1(current.0)?;
        let current_operation = safe_i64_v1(current.1)?;
        let current_budget = safe_i64_v1(current.2)?;
        let current_event = safe_i64_v1(current.3)?;
        if current_budget > current_store {
            return Err(StagingErrorV1::StoreUnhealthy);
        }
        let store = next_safe_v1(current_store)?;
        Ok(GenerationsV1 {
            store,
            operation: next_safe_v1(current_operation)?,
            // Reservation creation is bound to the enclosing store mutation. The schema's
            // budget high-water therefore advances to the same global generation.
            budget: store,
            event: next_safe_v1(current_event)?,
        })
    }

    fn stage_metadata_v1(
        transaction: &Transaction<'_>,
        generations: GenerationsV1,
    ) -> Result<(), StagingErrorV1> {
        let updated = transaction
            .execute(
                "UPDATE coordinator_store_meta SET \
                 store_generation = ?1, operation_generation = ?2, \
                 budget_generation = ?3, event_generation = ?4 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND store_generation = ?1 - 1 AND operation_generation = ?2 - 1 \
               AND event_generation = ?4 - 1 AND budget_generation <= ?1 - 1",
                params![
                    to_i64_v1(generations.store)?,
                    to_i64_v1(generations.operation)?,
                    to_i64_v1(generations.budget)?,
                    to_i64_v1(generations.event)?,
                ],
            )
            .map_err(map_mutation_error_v1)?;
        if updated != 1 {
            return Err(StagingErrorV1::StoreUnhealthy);
        }
        Ok(())
    }

    fn stage_operation_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        generations: GenerationsV1,
    ) -> Result<(), StagingErrorV1> {
        let input = bindings.commit;
        let context = input.final_context();
        let claims = input.eligible().authentic().preparation_claims();
        let canonical_plan = input
            .eligible()
            .authentic()
            .canonical_signed_envelope_bytes()
            .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        transaction
            .execute(
                "INSERT INTO prepared_operations (\
                 operation_id, attempt_id, plan_id, task_id, workload_id, canonical_plan, \
                 canonical_plan_length, operation_state, state_generation, created_generation, \
                 failed_generation, failed_reason_code, boot_id, instance_epoch, fencing_epoch, \
                 effective_expires_at_utc_ms, effective_deadline_monotonic_ms, reservation_id, \
                 recovery_mode, current_event_id, restored_source_generation\
             ) VALUES (\
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PREPARING', ?8, ?9, NULL, NULL, \
                 ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL\
             )",
                params![
                    claims.operation_id(),
                    input.attempt().as_bytes().as_slice(),
                    claims.plan_id().as_bytes().as_slice(),
                    claims.task_id(),
                    claims.workload_id(),
                    canonical_plan.as_slice(),
                    i64::try_from(canonical_plan.len())
                        .map_err(|_| StagingErrorV1::StoreUnhealthy)?,
                    to_i64_v1(generations.operation)?,
                    to_i64_v1(generations.store)?,
                    context.boot_id(),
                    to_i64_v1(context.instance_epoch())?,
                    to_i64_v1(context.fencing_epoch())?,
                    to_i64_v1(context.effective_expires_at_utc_ms())?,
                    to_i64_v1(context.effective_deadline_monotonic_ms())?,
                    claims.budget().reservation_id(),
                    recovery_class_text_v1(claims.recovery_class()),
                    bindings.event_id.as_bytes().as_slice(),
                ],
            )
            .map_err(map_mutation_error_v1)?;
        Ok(())
    }

    fn stage_transition_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        generations: GenerationsV1,
    ) -> Result<(), StagingErrorV1> {
        let operation_id = bindings.commit.final_context().operation_id();
        transaction
            .execute(
                "INSERT INTO operation_transitions (\
                 state_generation, operation_id, previous_state, new_state, event_id\
             ) VALUES (?1, ?2, NULL, 'PREPARING', ?3)",
                params![
                    to_i64_v1(generations.operation)?,
                    operation_id,
                    bindings.event_id.as_bytes().as_slice(),
                ],
            )
            .map_err(map_mutation_error_v1)?;
        Ok(())
    }

    fn stage_comparison_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        scope: &ScopeV1,
    ) -> Result<(), StagingErrorV1> {
        let input = bindings.commit;
        let context = input.final_context();
        let bounds = input.eligible().bounds();
        let provider_generation = match input.recovery_evidence() {
            RecoveryEvidenceV1::Material(receipt) => {
                Some(to_i64_v1(receipt.provider_generation())?)
            }
            RecoveryEvidenceV1::Irreversible(_) => None,
        };
        let placeholder = [0_u8; 32];
        transaction
        .execute(
            "INSERT INTO preparation_comparisons (\
                 operation_id, comparison_version, capture_generation, clock_generation, \
                 plan_deadline_generation, supervisor_generation, admission_state, \
                 instance_epoch, fencing_epoch, trust_generation, verified_key_fingerprint, \
                 workload_generation, workload_evidence_digest, lease_generation, \
                 lease_digest, lease_decision_digest, authorization_generation, \
                 authorization_evidence_digest, policy_generation, policy_decision_generation, \
                 policy_content_digest, policy_decision_digest, catalogue_generation, \
                 catalogue_decision_generation, catalogue_content_digest, \
                 catalogue_decision_digest, capability_generation, capability_report_digest, \
                 host_driver_context_digest, eligible_evaluated_at_utc_ms, \
                 eligible_evaluated_at_monotonic_ms, final_sample_utc_ms, \
                 final_sample_monotonic_ms, capability_observed_at_utc_ms, \
                 capability_max_age_ms, replay_claim_id, replay_claimant_generation, \
                 replay_binding_digest, budget_scope_id, budget_scope_generation, \
                 recovery_provider_generation, comparison_digest\
             ) VALUES (\
                 :operation_id, 1, :capture_generation, :clock_generation, \
                 :deadline_generation, :supervisor_generation, 'OPEN', :instance_epoch, \
                 :fencing_epoch, :trust_generation, :key_fingerprint, :workload_generation, \
                 :workload_digest, :lease_generation, :lease_digest, :lease_decision_digest, \
                 :authorization_generation, :authorization_digest, :policy_generation, \
                 :policy_decision_generation, :policy_content_digest, :policy_decision_digest, \
                 :catalogue_generation, :catalogue_decision_generation, \
                 :catalogue_content_digest, :catalogue_decision_digest, \
                 :capability_generation, :capability_report_digest, :driver_digest, \
                 :eligible_utc, :eligible_monotonic, :final_utc, :final_monotonic, \
                 :capability_observed_utc, :capability_max_age, :replay_claim_id, \
                 :replay_generation, :replay_binding_digest, :scope_id, :scope_generation, \
                 :provider_generation, :comparison_digest\
             )",
            named_params! {
                ":operation_id": context.operation_id(),
                ":capture_generation": to_i64_v1(context.capture_generation())?,
                ":clock_generation": to_i64_v1(context.clock_generation())?,
                ":deadline_generation": to_i64_v1(context.plan_deadline_generation())?,
                ":supervisor_generation": to_i64_v1(context.supervisor_generation())?,
                ":instance_epoch": to_i64_v1(context.instance_epoch())?,
                ":fencing_epoch": to_i64_v1(context.fencing_epoch())?,
                ":trust_generation": to_i64_v1(context.trust_generation())?,
                ":key_fingerprint": context.verified_key_fingerprint().as_bytes().as_slice(),
                ":workload_generation": to_i64_v1(context.workload_generation())?,
                ":workload_digest": context.workload_evidence_digest().as_bytes().as_slice(),
                ":lease_generation": to_i64_v1(context.lease_generation())?,
                ":lease_digest": context.lease_digest().as_bytes().as_slice(),
                ":lease_decision_digest": context.lease_decision_digest().as_bytes().as_slice(),
                ":authorization_generation": to_i64_v1(context.authorization_generation())?,
                ":authorization_digest": context.authorization_evidence_digest().as_bytes().as_slice(),
                ":policy_generation": to_i64_v1(context.policy_generation())?,
                ":policy_decision_generation": to_i64_v1(context.policy_decision_generation())?,
                ":policy_content_digest": context.policy_content_digest().as_bytes().as_slice(),
                ":policy_decision_digest": context.policy_decision_digest().as_bytes().as_slice(),
                ":catalogue_generation": to_i64_v1(context.catalogue_generation())?,
                ":catalogue_decision_generation": to_i64_v1(context.catalogue_decision_generation())?,
                ":catalogue_content_digest": context.catalogue_content_digest().as_bytes().as_slice(),
                ":catalogue_decision_digest": context.catalogue_decision_digest().as_bytes().as_slice(),
                ":capability_generation": to_i64_v1(context.capability_report_generation())?,
                ":capability_report_digest": context.capability_report_digest().as_bytes().as_slice(),
                ":driver_digest": context.host_driver_context_digest().as_bytes().as_slice(),
                ":eligible_utc": to_i64_v1(bounds.evaluated_at_utc_unix_ms())?,
                ":eligible_monotonic": to_i64_v1(bounds.evaluated_at_monotonic_ms())?,
                ":final_utc": to_i64_v1(context.sampled_utc_ms())?,
                ":final_monotonic": to_i64_v1(context.sampled_monotonic_ms())?,
                ":capability_observed_utc": to_i64_v1(context.capability_observed_at_utc_ms())?,
                ":capability_max_age": to_i64_v1(context.capability_max_age_ms())?,
                ":replay_claim_id": context.replay_claim_id().as_bytes().as_slice(),
                ":replay_generation": to_i64_v1(context.replay_claimant_generation())?,
                ":replay_binding_digest": context.replay_binding_digest().as_bytes().as_slice(),
                ":scope_id": scope.id.as_slice(),
                ":scope_generation": to_i64_v1(context.budget_scope_generation())?,
                ":provider_generation": provider_generation,
                ":comparison_digest": placeholder.as_slice(),
            },
        )
        .map_err(map_mutation_error_v1)?;
        Ok(())
    }

    fn stage_scope_delta_v1(
        transaction: &Transaction<'_>,
        _bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        scope: &ScopeV1,
    ) -> Result<(), StagingErrorV1> {
        let updated = transaction
            .execute(
                "UPDATE budget_scopes SET \
                 held_cost_micro_units = ?2, held_action_count = ?3, \
                 held_egress_bytes = ?4, held_recovery_bytes = ?5 \
             WHERE scope_id = ?1 \
               AND held_cost_micro_units = ?6 AND held_action_count = ?7 \
               AND held_egress_bytes = ?8 AND held_recovery_bytes = ?9",
                params![
                    scope.id.as_slice(),
                    to_i64_v1(scope.next_held[0])?,
                    to_i64_v1(scope.next_held[1])?,
                    to_i64_v1(scope.next_held[2])?,
                    to_i64_v1(scope.next_held[3])?,
                    to_i64_v1(scope.held[0])?,
                    to_i64_v1(scope.held[1])?,
                    to_i64_v1(scope.held[2])?,
                    to_i64_v1(scope.held[3])?,
                ],
            )
            .map_err(map_mutation_error_v1)?;
        if updated != 1 {
            return Err(StagingErrorV1::Conflict);
        }
        Ok(())
    }

    fn stage_reservation_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        scope: &ScopeV1,
        generations: GenerationsV1,
    ) -> Result<(), StagingErrorV1> {
        let input = bindings.commit;
        let context = input.final_context();
        let claims = input.eligible().authentic().preparation_claims();
        let requested = requested_vector_v1(input);
        transaction
            .execute(
                "INSERT INTO budget_reservations (\
                 reservation_id, operation_id, attempt_id, plan_id, scope_id, \
                 task_lease_digest, budget_generation, currency_code, price_table_id, \
                 reserved_cost_micro_units, reserved_action_count, reserved_egress_bytes, \
                 reserved_recovery_bytes, reservation_state, created_generation, \
                 released_generation\
             ) VALUES (\
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                 'HELD', ?14, NULL\
             )",
                params![
                    claims.budget().reservation_id(),
                    claims.operation_id(),
                    input.attempt().as_bytes().as_slice(),
                    claims.plan_id().as_bytes().as_slice(),
                    scope.id.as_slice(),
                    claims.task_lease_digest().as_bytes().as_slice(),
                    to_i64_v1(context.budget_scope_generation())?,
                    context.currency_code(),
                    context.price_table_id(),
                    to_i64_v1(requested[0])?,
                    to_i64_v1(requested[1])?,
                    to_i64_v1(requested[2])?,
                    to_i64_v1(requested[3])?,
                    to_i64_v1(generations.store)?,
                ],
            )
            .map_err(map_mutation_error_v1)?;
        Ok(())
    }

    fn stage_recovery_v1(
        transaction: &Transaction<'_>,
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
    ) -> Result<(), StagingErrorV1> {
        let input = bindings.commit;
        let context = input.final_context();
        let claims = input.eligible().authentic().preparation_claims();
        let risk = input
            .eligible()
            .authentic()
            .eligibility_claims()
            .risk_level();
        match input.recovery_evidence() {
            RecoveryEvidenceV1::Material(receipt) => {
                let evidence_class = match receipt.evidence_class() {
                    RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
                    RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
                };
                transaction
                .execute(
                    "INSERT INTO preparation_recovery_evidence (\
                         operation_id, evidence_version, recovery_mode, recovery_class, \
                         atomicity, risk_level, target_reference_digest, \
                         precondition_identity_digest, precondition_digest, precondition_length, \
                         reserved_capacity, provider_profile_id, provider_profile_version, \
                         provider_id, provider_generation, evidence_class, at_rest_profile_id, \
                         capability_binding_digest, material_id, publication_attempt_id, \
                         manifest_digest, material_digest, material_length, material_state, \
                         retirement_id, retirement_manifest_digest, retirement_generation, \
                         boot_binding_digest, instance_epoch, fencing_epoch\
                     ) VALUES (\
                         :operation_id, 1, 'COMPENSATION', 'COMPENSATION', :atomicity, \
                         :risk, :target_digest, :identity_digest, :precondition_digest, \
                         :precondition_length, :reserved_capacity, :profile_id, \
                         :profile_version, :provider_id, :provider_generation, :evidence_class, \
                         :at_rest_profile, :capability_digest, :material_id, \
                         :publication_attempt_id, :manifest_digest, :material_digest, \
                         :material_length, 'PUBLISHED', NULL, NULL, NULL, :boot_digest, \
                         :instance_epoch, :fencing_epoch\
                     )",
                    named_params! {
                        ":operation_id": claims.operation_id(),
                        ":atomicity": atomicity_text_v1(claims.atomicity()),
                        ":risk": risk_text_v1(risk),
                        ":target_digest": bindings.target_reference_digest.as_bytes().as_slice(),
                        ":identity_digest": bindings.precondition_identity_digest.as_bytes().as_slice(),
                        ":precondition_digest": claims.precondition_content_sha256().as_bytes().as_slice(),
                        ":precondition_length": to_i64_v1(claims.precondition_byte_length())?,
                        ":reserved_capacity": to_i64_v1(claims.recovery_reserved_bytes())?,
                        ":profile_id": receipt.provider_profile_id(),
                        ":profile_version": i64::from(receipt.provider_profile_version()),
                        ":provider_id": receipt.provider_id(),
                        ":provider_generation": to_i64_v1(receipt.provider_generation())?,
                        ":evidence_class": evidence_class,
                        ":at_rest_profile": receipt.at_rest_profile_id(),
                        ":capability_digest": receipt.capability_binding_digest().as_bytes().as_slice(),
                        ":material_id": receipt.material_id().as_bytes().as_slice(),
                        ":publication_attempt_id": receipt.publication_attempt_id().as_bytes().as_slice(),
                        ":manifest_digest": receipt.manifest_digest().as_bytes().as_slice(),
                        ":material_digest": receipt.material_digest().as_bytes().as_slice(),
                        ":material_length": to_i64_v1(receipt.material_length())?,
                        ":boot_digest": bindings.boot_binding_digest.as_bytes().as_slice(),
                        ":instance_epoch": to_i64_v1(context.instance_epoch())?,
                        ":fencing_epoch": to_i64_v1(context.fencing_epoch())?,
                    },
                )
                .map_err(map_mutation_error_v1)?;
            }
            RecoveryEvidenceV1::Irreversible(_) => {
                transaction
                    .execute(
                        "INSERT INTO preparation_recovery_evidence (\
                         operation_id, evidence_version, recovery_mode, recovery_class, \
                         atomicity, risk_level, target_reference_digest, \
                         precondition_identity_digest, precondition_digest, precondition_length, \
                         reserved_capacity, provider_profile_id, provider_profile_version, \
                         provider_id, provider_generation, evidence_class, at_rest_profile_id, \
                         capability_binding_digest, material_id, publication_attempt_id, \
                         manifest_digest, material_digest, material_length, material_state, \
                         retirement_id, retirement_manifest_digest, retirement_generation, \
                         boot_binding_digest, instance_epoch, fencing_epoch\
                     ) VALUES (\
                         ?1, 1, 'IRREVERSIBLE', 'IRREVERSIBLE', ?2, ?3, ?4, ?5, ?6, ?7, \
                         ?8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
                         NULL, NULL, NULL, NULL, NULL, NULL, ?9, ?10, ?11\
                     )",
                        params![
                            claims.operation_id(),
                            atomicity_text_v1(claims.atomicity()),
                            risk_text_v1(risk),
                            bindings.target_reference_digest.as_bytes().as_slice(),
                            bindings.precondition_identity_digest.as_bytes().as_slice(),
                            claims.precondition_content_sha256().as_bytes().as_slice(),
                            to_i64_v1(claims.precondition_byte_length())?,
                            to_i64_v1(claims.recovery_reserved_bytes())?,
                            bindings.boot_binding_digest.as_bytes().as_slice(),
                            to_i64_v1(context.instance_epoch())?,
                            to_i64_v1(context.fencing_epoch())?,
                        ],
                    )
                    .map_err(map_mutation_error_v1)?;
            }
        }
        Ok(())
    }

    fn finalize_production_comparison_digest_v1(
        transaction: &Transaction<'_>,
        operation_id: &str,
    ) -> Result<Sha256Digest, ()> {
        let digest = immutable_comparison_digest_for_operation_v1(transaction, operation_id)
            .map_err(|_| ())?;
        let updated = transaction
            .execute(
                "UPDATE preparation_comparisons SET comparison_digest = ?1 \
             WHERE operation_id = ?2",
                params![digest.as_slice(), operation_id],
            )
            .map_err(|_| ())?;
        if updated != 1 {
            return Err(());
        }
        Ok(Sha256Digest::from_bytes(digest))
    }

    fn verify_staged_foreign_keys_v1(transaction: &Transaction<'_>) -> Result<(), ()> {
        let has_violation = transaction
            .prepare("PRAGMA foreign_key_check")
            .and_then(|mut statement| statement.exists([]))
            .map_err(|_| ())?;
        if has_violation {
            return Err(());
        }
        Ok(())
    }

    fn build_commit_receipt_v1(
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        generations: GenerationsV1,
    ) -> Result<PreparationCommitReceiptV1, StagingErrorV1> {
        let reservation = BudgetReservationReceiptV1::try_new(BudgetReservationReceiptInputV1 {
            contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
            state: BudgetReservationStateV1::Held,
            reservation_generation: generations.store,
        })
        .map_err(|_| StagingErrorV1::StoreUnhealthy)?;
        PreparationCommitReceiptV1::try_new(PreparationCommitReceiptInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            attempt_id: bindings.commit.attempt().digest(),
            store_generation: generations.store,
            operation_state_generation: generations.operation,
            transition_generation: generations.operation,
            event_generation: generations.event,
            budget_reservation: reservation,
        })
        .map_err(|_| StagingErrorV1::StoreUnhealthy)
    }

    fn build_uncertain_custody_v1(
        bindings: &CoordinatorCommitBindingsV1<'_, '_>,
        generations: GenerationsV1,
        scope: &ScopeV1,
        comparison_digest: Sha256Digest,
    ) -> CoordinatorUncertainCommitCustodyV1 {
        let input = bindings.commit;
        let context = input.final_context();
        let claims = input.eligible().authentic().preparation_claims();
        CoordinatorUncertainCommitCustodyV1 {
            operation_id: claims.operation_id().to_owned(),
            attempt_id: input.attempt().digest(),
            plan_id: claims.plan_id(),
            reservation_id: claims.budget().reservation_id().to_owned(),
            event_id: bindings.event_id,
            scope_id: Sha256Digest::from_bytes(scope.id),
            budget_scope_binding_digest: context.budget_scope_binding_digest(),
            comparison_digest,
            replay_claim_id: context.replay_claim_id(),
            replay_claimant_generation: context.replay_claimant_generation(),
            replay_binding_digest: context.replay_binding_digest(),
            target_reference_digest: bindings.target_reference_digest,
            precondition_identity_digest: bindings.precondition_identity_digest,
            boot_binding_digest: bindings.boot_binding_digest,
            budget_scope_generation: context.budget_scope_generation(),
            store_generation: generations.store,
            operation_generation: generations.operation,
            event_generation: generations.event,
            reservation_created_generation: generations.store,
            supervisor_generation: context.supervisor_generation(),
            instance_epoch: context.instance_epoch(),
            fencing_epoch: context.fencing_epoch(),
        }
    }

    fn requested_vector_v1(input: &PreparationCommitInputV1<'_>) -> [u64; 4] {
        [
            input.requested_budget().max_cost_micro_units(),
            input.requested_budget().action_limit(),
            input.requested_budget().egress_bytes_limit(),
            input.requested_budget().recovery_bytes(),
        ]
    }

    fn pragma_i64_v1(connection: &Connection, name: &str) -> Result<i64, ()> {
        connection
            .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .map_err(|_| ())
    }

    fn safe_i64_v1(value: i64) -> Result<u64, StagingErrorV1> {
        u64::try_from(value)
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(StagingErrorV1::BudgetArithmeticInvalid)
    }

    fn to_i64_v1(value: u64) -> Result<i64, StagingErrorV1> {
        if value > MAX_SAFE_U64 {
            return Err(StagingErrorV1::BudgetArithmeticInvalid);
        }
        i64::try_from(value).map_err(|_| StagingErrorV1::BudgetArithmeticInvalid)
    }

    fn next_safe_v1(value: u64) -> Result<u64, StagingErrorV1> {
        value
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(StagingErrorV1::BudgetArithmeticInvalid)
    }

    fn recovery_class_text_v1(value: RecoveryClassV1) -> &'static str {
        match value {
            RecoveryClassV1::Compensation => "COMPENSATION",
            RecoveryClassV1::Irreversible => "IRREVERSIBLE",
        }
    }

    fn atomicity_text_v1(value: AtomicityV1) -> &'static str {
        match value {
            AtomicityV1::AtomicReplace => "ATOMIC_REPLACE",
            AtomicityV1::NonAtomic => "NON_ATOMIC",
        }
    }

    fn risk_text_v1(value: RiskLevelV1) -> &'static str {
        match value {
            RiskLevelV1::L0 => "L0",
            RiskLevelV1::L1 => "L1",
            RiskLevelV1::L2 => "L2",
        }
    }

    fn map_begin_error_v1(error: rusqlite::Error) -> StagingErrorV1 {
        match error {
            rusqlite::Error::SqliteFailure(failure, _)
                if matches!(
                    failure.code,
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                ) =>
            {
                StagingErrorV1::StoreBusy
            }
            rusqlite::Error::SqliteFailure(failure, _)
                if matches!(
                    failure.code,
                    ErrorCode::CannotOpen | ErrorCode::ReadOnly | ErrorCode::DiskFull
                ) =>
            {
                StagingErrorV1::StoreUnavailable
            }
            _ => StagingErrorV1::StoreUnhealthy,
        }
    }

    fn map_mutation_error_v1(error: rusqlite::Error) -> StagingErrorV1 {
        match error {
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == ErrorCode::ConstraintViolation
                    && matches!(failure.extended_code, 1_555 | 2_067) =>
            {
                // Only PRIMARY KEY/UNIQUE collisions are identity conflicts. CHECK,
                // NOT NULL, FK and trigger constraints indicate unhealthy staged data.
                StagingErrorV1::Conflict
            }
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == ErrorCode::ConstraintViolation =>
            {
                StagingErrorV1::StoreUnhealthy
            }
            other => map_begin_error_v1(other),
        }
    }

    fn map_staging_error_v1<I>(error: StagingErrorV1) -> CoordinatorCommitOutcomeV1<I> {
        match error {
            StagingErrorV1::StoreUnavailable => CoordinatorCommitOutcomeV1::StoreUnavailable,
            StagingErrorV1::StoreBusy => CoordinatorCommitOutcomeV1::StoreBusy,
            StagingErrorV1::StoreUnhealthy => CoordinatorCommitOutcomeV1::StoreUnhealthy,
            StagingErrorV1::OperationConflict => CoordinatorCommitOutcomeV1::OperationConflict,
            StagingErrorV1::AlreadyPrepared => CoordinatorCommitOutcomeV1::AlreadyPrepared,
            StagingErrorV1::Conflict => CoordinatorCommitOutcomeV1::Conflict,
            StagingErrorV1::BudgetScopeMissing => CoordinatorCommitOutcomeV1::BudgetScopeMissing,
            StagingErrorV1::BudgetBindingConflict => {
                CoordinatorCommitOutcomeV1::BudgetBindingConflict
            }
            StagingErrorV1::BudgetArithmeticInvalid => {
                CoordinatorCommitOutcomeV1::BudgetArithmeticInvalid
            }
            StagingErrorV1::BudgetExhausted => CoordinatorCommitOutcomeV1::BudgetExhausted,
        }
    }

    fn rollback_staging_error_v1<'connection>(
        transaction: Transaction<'connection>,
        error: StagingErrorV1,
    ) -> Result<StagedCommitV1<'connection>, StagingErrorV1> {
        if transaction.rollback().is_ok() {
            Err(error)
        } else {
            Err(StagingErrorV1::StoreUnhealthy)
        }
    }

    fn rollback_for_gate_refusal_v1<I>(
        transaction: Transaction<'_>,
        refusal: CoordinatorCommitOutcomeV1<I>,
    ) -> CoordinatorCommitOutcomeV1<I> {
        if transaction.rollback().is_ok() {
            refusal
        } else {
            CoordinatorCommitOutcomeV1::Unclassified
        }
    }

    fn rollback_unclassified_v1<I>(
        transaction: Option<Transaction<'_>>,
    ) -> CoordinatorCommitOutcomeV1<I> {
        if let Some(transaction) = transaction {
            let _ = transaction.rollback();
        }
        CoordinatorCommitOutcomeV1::Unclassified
    }

    #[inline]
    fn reach_root_accepted_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitCoordinatorRootAccepted
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_profile_accepted_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitCoordinatorProfileAccepted
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_invariants_accepted_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitCoordinatorInvariantsAccepted
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_begin_immediate_acquired_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitBeginImmediateAcquired
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_operation_identity_classified_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitOperationAttemptIdentityClassified
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_budget_scope_loaded_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitBudgetScopeLoaded.id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_final_arithmetic_capacity_classified_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitFinalArithmeticCapacityClassified
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_production_member_staged_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitMemberStaged.id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_sqlite_commit_invoked_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitSqliteCommitInvoked.id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[inline]
    fn reach_sqlite_commit_returned_v1(fault_probe: &CoordinatorFaultProbeV1) {
        #[cfg(feature = "test-fault-injection")]
        fault_probe.reach_id_v1(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitSqliteCommitReturnedWithTrustedClassification
                .id(),
        );
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = fault_probe;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use helix_plan_preparation::{
            FinalCommitReadbackResolutionV1, FinalCommitTerminalResolutionV1,
        };
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };

        struct ObservingPermit {
            active: Arc<AtomicBool>,
            calls: Arc<AtomicUsize>,
        }

        struct TestInFlight;

        impl FinalCommitPermitV1 for ObservingPermit {
            type InFlight = TestInFlight;

            fn permit_deadline_monotonic_ms(&self) -> u64 {
                1_000
            }

            fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
            where
                C: FnOnce() -> FinalCommitStoreClassificationV1,
            {
                assert!(!self.active.swap(true, Ordering::SeqCst));
                let classification = commit();
                assert!(self.active.swap(false, Ordering::SeqCst));
                self.calls.fetch_add(1, Ordering::SeqCst);
                match classification {
                    FinalCommitStoreClassificationV1::Committed => {
                        FinalCommitResolutionV1::Committed
                    }
                    FinalCommitStoreClassificationV1::ConfirmedRollback => {
                        FinalCommitResolutionV1::Aborted
                    }
                    FinalCommitStoreClassificationV1::Uncertain => {
                        FinalCommitResolutionV1::Uncertain(TestInFlight)
                    }
                    FinalCommitStoreClassificationV1::Unclassified => {
                        FinalCommitResolutionV1::Ambiguous
                    }
                }
            }
        }

        impl FinalCommitInFlightV1 for TestInFlight {
            fn permit_deadline_monotonic_ms(&self) -> u64 {
                1_000
            }

            fn resolve_readback(
                self,
                _resolution: FinalCommitReadbackResolutionV1,
            ) -> FinalCommitTerminalResolutionV1 {
                FinalCommitTerminalResolutionV1::Ambiguous
            }
        }

        #[test]
        fn actual_sqlite_commit_is_consumed_once_inside_live_permit() {
            let mut connection = Connection::open_in_memory().expect("database opens");
            connection
                .execute_batch("CREATE TABLE committed_once (value INTEGER NOT NULL)")
                .expect("table creates");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("writer begins");
            transaction
                .execute("INSERT INTO committed_once VALUES (1)", [])
                .expect("row stages");

            let active = Arc::new(AtomicBool::new(false));
            let calls = Arc::new(AtomicUsize::new(0));
            let permit = ObservingPermit {
                active: Arc::clone(&active),
                calls: Arc::clone(&calls),
            };
            let mut transaction = Some(transaction);
            let resolution = commit_sqlite_once_with_permit_v1(
                permit,
                &mut transaction,
                &CoordinatorFaultProbeV1::disabled_v1(),
            );

            assert!(matches!(resolution, FinalCommitResolutionV1::Committed));
            assert!(transaction.is_none(), "SQLite transaction was consumed");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "COMMIT closure called once"
            );
            assert!(
                !active.load(Ordering::SeqCst),
                "permit resolved after COMMIT"
            );
            drop(transaction);
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM committed_once", [], |row| row
                        .get::<_, i64>(0))
                    .expect("committed row reads"),
                1
            );
        }

        #[test]
        fn both_injected_full_verifications_observe_one_live_immediate_snapshot() {
            let mut connection = Connection::open_in_memory().expect("database opens");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("writer begins");
            let mut calls = 0_usize;
            let mut verifier = |snapshot: &Connection| {
                assert!(
                    !snapshot.is_autocommit(),
                    "full verification escaped the transaction snapshot"
                );
                calls += 1;
                Ok(())
            };

            assert!(verify_injected_full_snapshot_v1(&transaction, &mut verifier).is_ok());
            assert!(verify_injected_full_snapshot_v1(&transaction, &mut verifier).is_ok());

            assert_eq!(calls, 2, "both verification passes use the live snapshot");
            transaction.rollback().expect("writer rolls back");
        }

        #[test]
        fn verification_and_identity_errors_keep_their_closed_transaction_classes() {
            assert!(matches!(
                map_verification_error_v1(CoordinatorCommitVerificationErrorV1::Unavailable),
                StagingErrorV1::StoreUnavailable
            ));
            assert!(matches!(
                map_verification_error_v1(CoordinatorCommitVerificationErrorV1::Busy),
                StagingErrorV1::StoreBusy
            ));
            assert!(matches!(
                map_verification_error_v1(CoordinatorCommitVerificationErrorV1::Unhealthy),
                StagingErrorV1::StoreUnhealthy
            ));
            assert!(matches!(
                map_staging_error_v1::<TestInFlight>(StagingErrorV1::OperationConflict),
                CoordinatorCommitOutcomeV1::OperationConflict
            ));
            assert!(matches!(
                map_staging_error_v1::<TestInFlight>(StagingErrorV1::AlreadyPrepared),
                CoordinatorCommitOutcomeV1::AlreadyPrepared
            ));
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)] // Source-included T030 consumes this private fixture surface.
pub(crate) use synthetic::{
    commit_synthetic_preparation_until_v1, commit_synthetic_preparation_v1,
    provision_synthetic_budget_scope_v1, provision_synthetic_budget_scope_with_total_v1,
    SyntheticCommitModeV1, SyntheticConflictV1, SyntheticPreparationCaseV1,
    SyntheticRecoveryModeV1, CANONICAL_POSITIVE_MEMBER_COUNT_V1,
};

#[cfg(test)]
mod synthetic {
    use crate::comparison_digest::{
        immutable_comparison_digest_for_operation_v1, verify_persisted_comparison_digests_v1,
    };
    use crate::outbox::{stage_prepared_event_v1, PreparedEventRowV1};
    use crate::readback::{CoordinatorReadbackInputV1, SyntheticReadbackCaseV1};
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_contracts::{
        decode_and_verify_plan, sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError,
        Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128, PlanInputV1,
        RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1, RiskLevelV1,
        Sha256Digest, MAX_SAFE_U64,
    };
    use helix_plan_preparation::{
        recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
        recovery_target_reference_digest_v1, BudgetReservationReceiptInputV1,
        BudgetReservationReceiptV1, BudgetReservationStateV1, PreparationCommitOutcomeV1,
        PreparationCommitReceiptInputV1, PreparationCommitReceiptV1, PreparationCommitUncertainV1,
        PREPARATION_BUDGET_CONTRACT_VERSION_V1, PREPARATION_STORE_CONTRACT_VERSION_V1,
    };
    use rusqlite::{
        named_params, params, Connection, OpenFlags, OptionalExtension, Transaction,
        TransactionBehavior,
    };
    use std::path::Path;
    use std::time::Duration;

    pub(crate) const CANONICAL_POSITIVE_MEMBER_COUNT_V1: usize = 8;
    const ISSUED_AT_MS: u64 = 1_750_000_000_000;
    const PLAN_SIGNING_KEY_ID: &str = "core-signing-key:fixture-1";
    const PLAN_SIGNING_KEY_BYTES: [u8; 32] = [7; 32];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SyntheticRecoveryModeV1 {
        Compensation,
        Irreversible,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SyntheticConflictV1 {
        Plan,
        Replay,
        Budget,
        Recovery,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SyntheticCommitModeV1 {
        Acknowledged,
        ConfirmedRollbackAfterMember(usize),
        UncertainCommitted,
        UncertainRolledBack,
    }

    #[derive(Clone)]
    pub(crate) struct SyntheticPreparationCaseV1 {
        operation_id: String,
        attempt_id: Sha256Digest,
        plan_id: Sha256Digest,
        task_id: String,
        workload_id: String,
        canonical_plan: Vec<u8>,
        boot_id: String,
        instance_epoch: u64,
        fencing_epoch: u64,
        effective_expires_at_utc_ms: u64,
        effective_deadline_monotonic_ms: u64,
        reservation_id: String,
        recovery_mode: RecoveryClassV1,
        atomicity: AtomicityV1,
        risk_level: RiskLevelV1,
        task_lease_digest: Sha256Digest,
        currency_code: String,
        price_table_id: String,
        requested: [u64; 4],
        scope_id: Sha256Digest,
        allowance_binding_digest: Sha256Digest,
        scope_generation: u64,
        verified_key_fingerprint: Sha256Digest,
        capability_report_digest: Sha256Digest,
        replay_claim_id: Sha256Digest,
        replay_claimant_generation: u64,
        replay_binding_digest: Sha256Digest,
        event_id: Sha256Digest,
        precondition_digest: Sha256Digest,
        precondition_length: u64,
        target_reference_digest: Sha256Digest,
        precondition_identity_digest: Sha256Digest,
        boot_binding_digest: Sha256Digest,
        recovery_variant_digest: Sha256Digest,
    }

    impl SyntheticPreparationCaseV1 {
        pub(crate) fn coherent_v1(mode: SyntheticRecoveryModeV1) -> Self {
            Self::from_plan_input_v1(plan_input_v1(mode), None)
        }

        fn from_plan_input_v1(
            input: PlanInputV1,
            shared_scope: Option<(Sha256Digest, Sha256Digest, u64)>,
        ) -> Self {
            let signer = SyntheticPlanSignerV1::new();
            let signed = sign_plan_v1(input, &signer).expect("public-synthetic plan signs");
            let canonical_plan = signed
                .to_canonical_json()
                .expect("public-synthetic plan canonicalizes");
            let authentic = decode_and_verify_plan(&canonical_plan, &SyntheticPlanResolverV1)
                .expect("public-synthetic plan verifies");
            let claims = authentic.preparation_claims();
            let eligibility = authentic.eligibility_claims();
            let recovery_mode = claims.recovery_class();
            let mode_label = match recovery_mode {
                RecoveryClassV1::Compensation => b"compensation".as_slice(),
                RecoveryClassV1::Irreversible => b"irreversible".as_slice(),
            };
            let default_scope = (
                digest_parts(b"scope", &[claims.task_lease_digest().as_bytes()]),
                digest_parts(
                    b"allowance",
                    &[claims.task_lease_digest().as_bytes(), mode_label],
                ),
                1,
            );
            let (scope_id, allowance_binding_digest, scope_generation) =
                shared_scope.unwrap_or(default_scope);
            Self {
                operation_id: claims.operation_id().to_owned(),
                attempt_id: digest_parts(b"attempt", &[authentic.plan_id().as_bytes(), mode_label]),
                plan_id: authentic.plan_id(),
                task_id: claims.task_id().to_owned(),
                workload_id: claims.workload_id().to_owned(),
                canonical_plan,
                boot_id: eligibility.boot_id().to_owned(),
                instance_epoch: eligibility.instance_epoch(),
                fencing_epoch: eligibility.fencing_epoch(),
                effective_expires_at_utc_ms: eligibility.expires_at_unix_ms(),
                effective_deadline_monotonic_ms: 60_000,
                reservation_id: claims.budget().reservation_id().to_owned(),
                recovery_mode,
                atomicity: claims.atomicity(),
                risk_level: eligibility.risk_level(),
                task_lease_digest: claims.task_lease_digest(),
                currency_code: claims.budget().currency_code().to_owned(),
                price_table_id: claims.budget().price_table_id().to_owned(),
                requested: [
                    claims.budget().max_cost_micro_units(),
                    claims.budget().action_limit(),
                    claims.budget().egress_bytes_limit(),
                    claims.recovery_reserved_bytes(),
                ],
                scope_id,
                allowance_binding_digest,
                scope_generation,
                verified_key_fingerprint: eligibility.verified_key_fingerprint(),
                capability_report_digest: eligibility.capability_report_digest(),
                replay_claim_id: digest_parts(b"replay-claim", &[authentic.plan_id().as_bytes()]),
                replay_claimant_generation: 1,
                replay_binding_digest: digest_parts(
                    b"replay-binding",
                    &[authentic.plan_id().as_bytes()],
                ),
                event_id: digest_parts(
                    b"prepared-event",
                    &[authentic.plan_id().as_bytes(), mode_label],
                ),
                precondition_digest: claims.precondition_content_sha256(),
                precondition_length: claims.precondition_byte_length(),
                target_reference_digest: recovery_target_reference_digest_v1(claims.target())
                    .expect("synthetic target reference has a canonical v1 digest"),
                precondition_identity_digest: recovery_precondition_identity_digest_v1(
                    claims.precondition_volume_id(),
                    claims.precondition_file_id(),
                )
                .expect("synthetic precondition identity has a canonical v1 digest"),
                boot_binding_digest: recovery_boot_binding_digest_v1(
                    eligibility.boot_id(),
                    eligibility.instance_epoch(),
                    eligibility.fencing_epoch(),
                )
                .expect("synthetic boot binding has a canonical v1 digest"),
                recovery_variant_digest: digest_parts(
                    b"recovery-variant",
                    &[authentic.plan_id().as_bytes(), mode_label],
                ),
            }
        }

        /// Builds a fully signed distinct operation while retaining exactly one shared
        /// provisioned scope identity and allowance binding from `self`.
        pub(crate) fn distinct_operation_in_shared_scope_v1(
            &self,
            ordinal: u64,
            requested: [u64; 4],
        ) -> Self {
            let mode = match self.recovery_mode {
                RecoveryClassV1::Compensation => SyntheticRecoveryModeV1::Compensation,
                RecoveryClassV1::Irreversible => SyntheticRecoveryModeV1::Irreversible,
            };
            let mut input = plan_input_v1(mode);
            input.operation_id = format!("operation:shared-scope-{ordinal}");
            input.budget.reservation_id = format!("budget:shared-scope-{ordinal}");
            input.budget.max_cost_micro_units = requested[0];
            input.budget.action_limit = requested[1];
            input.budget.egress_bytes_limit = requested[2];
            input.recovery.reserved_bytes = requested[3];
            let mut nonce = [0x73_u8; 16];
            nonce[8..].copy_from_slice(&ordinal.to_be_bytes());
            input.nonce = Nonce128::from_bytes(nonce);
            Self::from_plan_input_v1(
                input,
                Some((
                    self.scope_id,
                    self.allowance_binding_digest,
                    self.scope_generation,
                )),
            )
        }

        pub(crate) fn conflicting_v1(&self, conflict: SyntheticConflictV1) -> Self {
            let mut changed = self.clone();
            match conflict {
                SyntheticConflictV1::Plan => changed.plan_id = digest(b"conflicting plan"),
                SyntheticConflictV1::Replay => {
                    changed.replay_claim_id = digest(b"conflicting replay")
                }
                SyntheticConflictV1::Budget => {
                    changed.allowance_binding_digest = digest(b"conflicting budget")
                }
                SyntheticConflictV1::Recovery => {
                    changed.recovery_variant_digest = digest(b"conflicting recovery")
                }
            }
            changed
        }

        pub(crate) fn next_exact_attempt_v1(&self) -> Self {
            let mut next = self.clone();
            next.attempt_id = digest_parts(b"next-attempt", &[self.attempt_id.as_bytes()]);
            next
        }
    }

    impl SyntheticReadbackCaseV1 for SyntheticPreparationCaseV1 {
        fn coordinator_readback_input_v1(&self) -> CoordinatorReadbackInputV1<'_> {
            CoordinatorReadbackInputV1 {
                operation_id: &self.operation_id,
                attempt_id: self.attempt_id,
                plan_id: self.plan_id,
                task_id: &self.task_id,
                workload_id: &self.workload_id,
                reservation_id: &self.reservation_id,
                replay_claim_id: self.replay_claim_id,
                replay_claimant_generation: self.replay_claimant_generation,
                replay_binding_digest: self.replay_binding_digest,
                task_lease_digest: self.task_lease_digest,
                allowance_binding_digest: self.allowance_binding_digest,
                scope_generation: self.scope_generation,
                currency_code: &self.currency_code,
                price_table_id: &self.price_table_id,
                requested: self.requested,
                recovery_mode: self.recovery_mode,
                precondition_digest: self.precondition_digest,
                precondition_length: self.precondition_length,
                effective_expires_at_utc_ms: self.effective_expires_at_utc_ms,
                effective_deadline_monotonic_ms: self.effective_deadline_monotonic_ms,
                exact_custody: None,
                full_store_verified: false,
                definite_absence_writer_exclusion: false,
            }
        }

        fn verify_synthetic_full_store_v1(&self, connection: &Connection) -> bool {
            verify_synthetic_store_v1(connection)
        }
    }

    pub(crate) fn provision_synthetic_budget_scope_v1(
        database: &Path,
        case: &SyntheticPreparationCaseV1,
    ) -> rusqlite::Result<()> {
        provision_synthetic_budget_scope_with_total_v1(database, case, case.requested)
    }

    pub(crate) fn provision_synthetic_budget_scope_with_total_v1(
        database: &Path,
        case: &SyntheticPreparationCaseV1,
        total: [u64; 4],
    ) -> rusqlite::Result<()> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(database, flags)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT INTO budget_scopes (
                 scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
                 currency_code, price_table_id, total_cost_micro_units, total_action_count,
                 total_egress_bytes, total_recovery_bytes, held_cost_micro_units,
                 held_action_count, held_egress_bytes, held_recovery_bytes,
                 provisioning_profile
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, 0, 0,
                       'TRUSTED_LEASE_V1')",
            params![
                case.scope_id.as_bytes().as_slice(),
                case.task_lease_digest.as_bytes().as_slice(),
                case.allowance_binding_digest.as_bytes().as_slice(),
                case.scope_generation as i64,
                case.currency_code,
                case.price_table_id,
                i64::try_from(total[0]).map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::try_from(total[1]).map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::try_from(total[2]).map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::try_from(total[3]).map_err(|_| rusqlite::Error::InvalidQuery)?,
            ],
        )?;
        if inserted != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let updated = transaction.execute(
            "UPDATE coordinator_store_meta
             SET store_generation = 1, budget_generation = 1
             WHERE singleton = 1 AND store_generation = 0 AND budget_generation = 0",
            [],
        )?;
        if updated != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()
    }

    pub(crate) fn commit_synthetic_preparation_v1(
        database: &Path,
        case: &SyntheticPreparationCaseV1,
        mode: SyntheticCommitModeV1,
    ) -> PreparationCommitOutcomeV1 {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = match Connection::open_with_flags(database, flags) {
            Ok(connection) => connection,
            Err(_) => return PreparationCommitOutcomeV1::Unavailable,
        };
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => return PreparationCommitOutcomeV1::Busy,
        };
        commit_synthetic_preparation_transaction_v1(transaction, case, mode, || {
            SyntheticPrecommitClockV1::Live
        })
    }

    /// Test-only counterpart of the real deadline-bounded connection path.
    ///
    /// It configures SQLite's native busy handler once from the injected absolute
    /// deadline, rechecks equality after writer acquisition and immediately before
    /// COMMIT, and never launches retry or cancellation work outside this call.
    pub(crate) fn commit_synthetic_preparation_until_v1<C>(
        database: &Path,
        case: &SyntheticPreparationCaseV1,
        mode: SyntheticCommitModeV1,
        clock: &C,
        deadline_monotonic_ms: u64,
        maximum_busy_wait_ms: u64,
    ) -> PreparationCommitOutcomeV1
    where
        C: ::helix_coordinator_sqlite::CoordinatorMonotonicClockV1 + ?Sized,
    {
        if deadline_monotonic_ms > MAX_SAFE_U64 || maximum_busy_wait_ms == 0 {
            return PreparationCommitOutcomeV1::PermitDeadlineReached;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = match Connection::open_with_flags(database, flags) {
            Ok(connection) => connection,
            Err(_) => return PreparationCommitOutcomeV1::Unavailable,
        };
        let remaining = match synthetic_remaining_monotonic_ms_v1(clock, deadline_monotonic_ms) {
            Ok(remaining) => remaining,
            Err(SyntheticPrecommitClockV1::DeadlineReached) => {
                return PreparationCommitOutcomeV1::PermitDeadlineReached
            }
            Err(SyntheticPrecommitClockV1::Unavailable) => {
                return PreparationCommitOutcomeV1::Unavailable
            }
            Err(SyntheticPrecommitClockV1::Live) => {
                return PreparationCommitOutcomeV1::Unclassified
            }
        };
        let busy_timeout_ms = remaining
            .min(maximum_busy_wait_ms)
            .min(i32::MAX as u64)
            .max(1);
        if connection
            .busy_timeout(Duration::from_millis(busy_timeout_ms))
            .is_err()
        {
            return PreparationCommitOutcomeV1::Unavailable;
        }
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => return PreparationCommitOutcomeV1::Busy,
        };
        match sample_synthetic_clock_v1(clock, deadline_monotonic_ms) {
            SyntheticPrecommitClockV1::Live => {}
            SyntheticPrecommitClockV1::DeadlineReached => {
                return if transaction.rollback().is_ok() {
                    PreparationCommitOutcomeV1::PermitDeadlineReached
                } else {
                    PreparationCommitOutcomeV1::Unclassified
                };
            }
            SyntheticPrecommitClockV1::Unavailable => {
                return if transaction.rollback().is_ok() {
                    PreparationCommitOutcomeV1::Unavailable
                } else {
                    PreparationCommitOutcomeV1::Unclassified
                };
            }
        }
        commit_synthetic_preparation_transaction_v1(transaction, case, mode, || {
            sample_synthetic_clock_v1(clock, deadline_monotonic_ms)
        })
    }

    enum SyntheticPrecommitClockV1 {
        Live,
        DeadlineReached,
        Unavailable,
    }

    fn sample_synthetic_clock_v1<C>(
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> SyntheticPrecommitClockV1
    where
        C: ::helix_coordinator_sqlite::CoordinatorMonotonicClockV1 + ?Sized,
    {
        match clock.now_monotonic_ms() {
            Ok(now) if now <= MAX_SAFE_U64 && now < deadline_monotonic_ms => {
                SyntheticPrecommitClockV1::Live
            }
            Ok(_) => SyntheticPrecommitClockV1::DeadlineReached,
            Err(_) => SyntheticPrecommitClockV1::Unavailable,
        }
    }

    fn synthetic_remaining_monotonic_ms_v1<C>(
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<u64, SyntheticPrecommitClockV1>
    where
        C: ::helix_coordinator_sqlite::CoordinatorMonotonicClockV1 + ?Sized,
    {
        match clock.now_monotonic_ms() {
            Ok(now) if now <= MAX_SAFE_U64 => deadline_monotonic_ms
                .checked_sub(now)
                .filter(|remaining| *remaining > 0)
                .ok_or(SyntheticPrecommitClockV1::DeadlineReached),
            Ok(_) => Err(SyntheticPrecommitClockV1::DeadlineReached),
            Err(_) => Err(SyntheticPrecommitClockV1::Unavailable),
        }
    }

    fn commit_synthetic_preparation_transaction_v1<F>(
        transaction: Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
        mode: SyntheticCommitModeV1,
        mut precommit_clock: F,
    ) -> PreparationCommitOutcomeV1
    where
        F: FnMut() -> SyntheticPrecommitClockV1,
    {
        if relevant_identity_exists(&transaction, case).unwrap_or(true) {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Conflict;
        }
        match classify_synthetic_scope_v1(&transaction, case) {
            Ok(SyntheticScopeClassificationV1::Exact) => {}
            Ok(SyntheticScopeClassificationV1::Exhausted) => {
                let _ = transaction.rollback();
                return PreparationCommitOutcomeV1::BudgetExhausted;
            }
            Ok(SyntheticScopeClassificationV1::Conflict) => {
                let _ = transaction.rollback();
                return PreparationCommitOutcomeV1::Conflict;
            }
            Err(()) => {
                let _ = transaction.rollback();
                return PreparationCommitOutcomeV1::Unhealthy;
            }
        }

        let generations = match allocate_synthetic_generations_v1(&transaction) {
            Some(generations) => generations,
            None => {
                let _ = transaction.rollback();
                return PreparationCommitOutcomeV1::Unhealthy;
            }
        };

        if stage_metadata(&transaction, generations).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }
        if rollback_after(&transaction, mode, 1) {
            return rollback_member(transaction);
        }
        if stage_operation(&transaction, case, generations.store, generations.operation).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Conflict;
        }
        if rollback_after(&transaction, mode, 2) {
            return rollback_member(transaction);
        }
        if stage_transition(&transaction, case, generations.operation).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }
        if rollback_after(&transaction, mode, 3) {
            return rollback_member(transaction);
        }
        if stage_comparison(&transaction, case).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }
        if rollback_after(&transaction, mode, 4) {
            return rollback_member(transaction);
        }
        if stage_scope_delta(&transaction, case).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Conflict;
        }
        if rollback_after(&transaction, mode, 5) {
            return rollback_member(transaction);
        }
        if stage_reservation(&transaction, case, generations.store).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Conflict;
        }
        if rollback_after(&transaction, mode, 6) {
            return rollback_member(transaction);
        }
        if stage_recovery(&transaction, case).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }
        if rollback_after(&transaction, mode, 7) {
            return rollback_member(transaction);
        }
        if stage_prepared_event_v1(
            &transaction,
            PreparedEventRowV1 {
                event_id: case.event_id.as_bytes(),
                event_generation: generations.event,
                operation_id: &case.operation_id,
                operation_state_generation: generations.operation,
            },
        )
        .is_err()
        {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }
        reach_member_staged();
        if rollback_after(&transaction, mode, 8) {
            return rollback_member(transaction);
        }
        if finalize_all_synthetic_comparison_digests_v1(&transaction).is_err() {
            let _ = transaction.rollback();
            return PreparationCommitOutcomeV1::Unhealthy;
        }

        let receipt = match commit_receipt(
            case,
            generations.store as u64,
            generations.operation as u64,
            generations.event as u64,
            generations.store as u64,
        ) {
            Some(receipt) => receipt,
            None => {
                let _ = transaction.rollback();
                return PreparationCommitOutcomeV1::Unhealthy;
            }
        };
        match mode {
            SyntheticCommitModeV1::UncertainRolledBack => {
                if transaction.rollback().is_err() {
                    return PreparationCommitOutcomeV1::Unclassified;
                }
                uncertain(case)
            }
            SyntheticCommitModeV1::Acknowledged | SyntheticCommitModeV1::UncertainCommitted => {
                match precommit_clock() {
                    SyntheticPrecommitClockV1::Live => {}
                    SyntheticPrecommitClockV1::DeadlineReached => {
                        return if transaction.rollback().is_ok() {
                            PreparationCommitOutcomeV1::PermitDeadlineReached
                        } else {
                            PreparationCommitOutcomeV1::Unclassified
                        };
                    }
                    SyntheticPrecommitClockV1::Unavailable => {
                        return if transaction.rollback().is_ok() {
                            PreparationCommitOutcomeV1::Unavailable
                        } else {
                            PreparationCommitOutcomeV1::Unclassified
                        };
                    }
                }
                if transaction.commit().is_err() {
                    return PreparationCommitOutcomeV1::Unclassified;
                }
                if mode == SyntheticCommitModeV1::Acknowledged {
                    PreparationCommitOutcomeV1::Committed(receipt)
                } else {
                    uncertain(case)
                }
            }
            SyntheticCommitModeV1::ConfirmedRollbackAfterMember(_) => {
                let _ = transaction.rollback();
                PreparationCommitOutcomeV1::ConfirmedRollback
            }
        }
    }

    fn plan_input_v1(mode: SyntheticRecoveryModeV1) -> PlanInputV1 {
        let irreversible = mode == SyntheticRecoveryModeV1::Irreversible;
        PlanInputV1 {
            operation_id: "operation:00000000-0000-4000-8000-000000000001".to_owned(),
            task_id: "task:fixture-1".to_owned(),
            workload_id: "workload:agent-vm-1".to_owned(),
            boot_id: "boot:fixture-1".to_owned(),
            task_lease_digest: digest(b"fixture task lease"),
            request_source_kind: RequestSourceKindV1::HumanRequestGrant,
            request_source_digest: digest(b"fixture human request grant"),
            catalog_version: "catalog:1".to_owned(),
            policy_version: "policy:1".to_owned(),
            risk_level: if irreversible {
                RiskLevelV1::L2
            } else {
                RiskLevelV1::L1
            },
            target: ResourceRefV1::new("vault-main", ["Projects", "HelixOS", "Decision.md"])
                .expect("synthetic resource is valid"),
            precondition: FilePreconditionInputV1 {
                volume_id: "volume:fixture-apfs".to_owned(),
                file_id: "file:00000042".to_owned(),
                content_sha256: digest(b"before\n"),
                byte_length: 7,
            },
            replacement_bytes: b"after\n".to_vec(),
            replacement_media_type: "text/markdown;charset=utf-8".to_owned(),
            recovery: RecoveryInputV1 {
                class: if irreversible {
                    RecoveryClassV1::Irreversible
                } else {
                    RecoveryClassV1::Compensation
                },
                atomicity: AtomicityV1::AtomicReplace,
                reserved_bytes: 4_096,
            },
            capability_report_digest: digest(b"fixture capability report"),
            capability_observed_at_unix_ms: ISSUED_AT_MS - 1_000,
            required_capabilities: vec![
                "filesystem.verify-by-handle".to_owned(),
                "filesystem.atomic-replace".to_owned(),
            ],
            budget: BudgetInputV1 {
                reservation_id: "budget:fixture-1".to_owned(),
                currency_code: "EUR".to_owned(),
                price_table_id: "price-table:fixture-1".to_owned(),
                max_cost_micro_units: 0,
                action_limit: 1,
                egress_bytes_limit: 0,
            },
            issued_at_unix_ms: ISSUED_AT_MS,
            expires_at_unix_ms: ISSUED_AT_MS + 120_000,
            nonce: Nonce128::from_bytes([0x11; 16]),
            instance_epoch: 1,
            fencing_epoch: 9,
        }
    }

    struct SyntheticPlanSignerV1(SigningKey);

    impl SyntheticPlanSignerV1 {
        fn new() -> Self {
            Self(SigningKey::from_bytes(&PLAN_SIGNING_KEY_BYTES))
        }
    }

    impl Ed25519Signer for SyntheticPlanSignerV1 {
        fn key_id(&self) -> &str {
            PLAN_SIGNING_KEY_ID
        }

        fn sign_ed25519(&self, message: &[u8]) -> helix_contracts::Result<[u8; 64]> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    struct SyntheticPlanResolverV1;

    impl Ed25519KeyResolver for SyntheticPlanResolverV1 {
        fn resolve_ed25519(&self, key_id: &str) -> helix_contracts::Result<[u8; 32]> {
            if key_id == PLAN_SIGNING_KEY_ID {
                Ok(SigningKey::from_bytes(&PLAN_SIGNING_KEY_BYTES)
                    .verifying_key()
                    .to_bytes())
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    fn relevant_identity_exists(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
    ) -> rusqlite::Result<bool> {
        transaction.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM prepared_operations
                 WHERE operation_id = ?1 OR attempt_id = ?2 OR plan_id = ?3
                    OR reservation_id = ?4 OR current_event_id = ?5
             )",
            params![
                case.operation_id,
                case.attempt_id.as_bytes().as_slice(),
                case.plan_id.as_bytes().as_slice(),
                case.reservation_id,
                case.event_id.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
    }

    enum SyntheticScopeClassificationV1 {
        Exact,
        Exhausted,
        Conflict,
    }

    fn classify_synthetic_scope_v1(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
    ) -> Result<SyntheticScopeClassificationV1, ()> {
        let row = transaction
            .query_row(
                "SELECT total_cost_micro_units, total_action_count, total_egress_bytes,
                        total_recovery_bytes, held_cost_micro_units, held_action_count,
                        held_egress_bytes, held_recovery_bytes
             FROM budget_scopes
             WHERE scope_id = ?1 AND task_lease_digest = ?2
               AND allowance_binding_digest = ?3 AND scope_generation = ?4
               AND currency_code = ?5 AND price_table_id = ?6",
                params![
                    case.scope_id.as_bytes().as_slice(),
                    case.task_lease_digest.as_bytes().as_slice(),
                    case.allowance_binding_digest.as_bytes().as_slice(),
                    i64::try_from(case.scope_generation).map_err(|_| ())?,
                    case.currency_code,
                    case.price_table_id,
                ],
                |row| {
                    Ok((
                        [row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?],
                        [row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?],
                    ))
                },
            )
            .optional()
            .map_err(|_| ())?;
        let Some((total, held)): Option<([i64; 4], [i64; 4])> = row else {
            return Ok(SyntheticScopeClassificationV1::Conflict);
        };
        for index in 0..4 {
            let total = u64::try_from(total[index]).map_err(|_| ())?;
            let held = u64::try_from(held[index]).map_err(|_| ())?;
            let remaining = total.checked_sub(held).ok_or(())?;
            if case.requested[index] > remaining {
                return Ok(SyntheticScopeClassificationV1::Exhausted);
            }
        }
        Ok(SyntheticScopeClassificationV1::Exact)
    }

    #[derive(Clone, Copy)]
    struct SyntheticGenerationsV1 {
        current_store: i64,
        current_operation: i64,
        current_budget: i64,
        current_event: i64,
        store: i64,
        operation: i64,
        budget: i64,
        event: i64,
    }

    fn allocate_synthetic_generations_v1(
        transaction: &Transaction<'_>,
    ) -> Option<SyntheticGenerationsV1> {
        let (current_store, current_operation, current_budget, current_event): (
            i64,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT store_generation, operation_generation, budget_generation,
                        event_generation FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok()?;
        if current_store < 0
            || current_operation < 0
            || current_budget < 0
            || current_event < 0
            || current_budget > current_store
        {
            return None;
        }
        let store = current_store.checked_add(1)?;
        Some(SyntheticGenerationsV1 {
            current_store,
            current_operation,
            current_budget,
            current_event,
            store,
            operation: current_operation.checked_add(1)?,
            budget: store,
            event: current_event.checked_add(1)?,
        })
    }

    fn stage_metadata(
        transaction: &Transaction<'_>,
        generations: SyntheticGenerationsV1,
    ) -> rusqlite::Result<()> {
        let updated = transaction.execute(
            "UPDATE coordinator_store_meta
             SET store_generation = ?1, operation_generation = ?2,
                 budget_generation = ?3, event_generation = ?4
             WHERE singleton = 1 AND store_generation = ?5
               AND operation_generation = ?6 AND budget_generation = ?7
               AND event_generation = ?8",
            params![
                generations.store,
                generations.operation,
                generations.budget,
                generations.event,
                generations.current_store,
                generations.current_operation,
                generations.current_budget,
                generations.current_event,
            ],
        )?;
        if updated != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        reach_member_staged();
        Ok(())
    }

    fn stage_operation(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
        store_generation: i64,
        state_generation: i64,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            "INSERT INTO prepared_operations (
                 operation_id, attempt_id, plan_id, task_id, workload_id, canonical_plan,
                 canonical_plan_length, operation_state, state_generation, created_generation,
                 failed_generation, failed_reason_code, boot_id, instance_epoch, fencing_epoch,
                 effective_expires_at_utc_ms, effective_deadline_monotonic_ms, reservation_id,
                 recovery_mode, current_event_id, restored_source_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PREPARING', ?8, ?9, NULL, NULL,
                       ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL)",
            params![
                case.operation_id,
                case.attempt_id.as_bytes().as_slice(),
                case.plan_id.as_bytes().as_slice(),
                case.task_id,
                case.workload_id,
                case.canonical_plan,
                case.canonical_plan.len() as i64,
                state_generation,
                store_generation,
                case.boot_id,
                case.instance_epoch as i64,
                case.fencing_epoch as i64,
                case.effective_expires_at_utc_ms as i64,
                case.effective_deadline_monotonic_ms as i64,
                case.reservation_id,
                recovery_mode_text(case.recovery_mode),
                case.event_id.as_bytes().as_slice(),
            ],
        )?;
        reach_member_staged();
        Ok(())
    }

    fn stage_transition(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
        state_generation: i64,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            "INSERT INTO operation_transitions (
                 state_generation, operation_id, previous_state, new_state, event_id
             ) VALUES (?1, ?2, NULL, 'PREPARING', ?3)",
            params![
                state_generation,
                case.operation_id,
                case.event_id.as_bytes().as_slice()
            ],
        )?;
        reach_member_staged();
        Ok(())
    }

    fn stage_comparison(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
    ) -> rusqlite::Result<()> {
        let zero = [0_u8; 32];
        let provider_generation = match case.recovery_mode {
            RecoveryClassV1::Compensation => Some(1_i64),
            RecoveryClassV1::Irreversible => None,
        };
        transaction.execute(
            "INSERT INTO preparation_comparisons (
                 operation_id, comparison_version, capture_generation, clock_generation,
                 plan_deadline_generation, supervisor_generation, admission_state,
                 instance_epoch, fencing_epoch, trust_generation, verified_key_fingerprint,
                 workload_generation, workload_evidence_digest, lease_generation,
                 lease_digest, lease_decision_digest, authorization_generation,
                 authorization_evidence_digest, policy_generation, policy_decision_generation,
                 policy_content_digest, policy_decision_digest, catalogue_generation,
                 catalogue_decision_generation, catalogue_content_digest,
                 catalogue_decision_digest, capability_generation, capability_report_digest,
                 host_driver_context_digest, eligible_evaluated_at_utc_ms,
                 eligible_evaluated_at_monotonic_ms, final_sample_utc_ms,
                 final_sample_monotonic_ms, capability_observed_at_utc_ms,
                 capability_max_age_ms, replay_claim_id, replay_claimant_generation,
                 replay_binding_digest, budget_scope_id, budget_scope_generation,
                 recovery_provider_generation, comparison_digest
             ) VALUES (
                 :operation_id, 1, 1, 1, 1, 1, 'OPEN', :instance_epoch, :fencing_epoch,
                 1, :key_fingerprint, 1, :workload_digest, 1, :lease_digest,
                 :lease_decision_digest, 1, :authorization_digest, 1, 1,
                 :policy_content_digest, :policy_decision_digest, 1, 1,
                 :catalogue_content_digest, :catalogue_decision_digest, 1,
                 :capability_report_digest, :driver_digest, :evaluated_utc,
                 100, :final_utc, 101, :observed_utc, 120000, :replay_claim_id,
                 :replay_generation, :replay_binding_digest, :scope_id, :scope_generation,
                 :provider_generation, :comparison_digest
             )",
            named_params! {
                ":operation_id": case.operation_id,
                ":instance_epoch": case.instance_epoch as i64,
                ":fencing_epoch": case.fencing_epoch as i64,
                ":key_fingerprint": case.verified_key_fingerprint.as_bytes().as_slice(),
                ":workload_digest": digest(b"workload evidence").as_bytes().as_slice(),
                ":lease_digest": case.task_lease_digest.as_bytes().as_slice(),
                ":lease_decision_digest": digest(b"lease decision").as_bytes().as_slice(),
                ":authorization_digest": digest(b"authorization evidence").as_bytes().as_slice(),
                ":policy_content_digest": digest(b"policy content").as_bytes().as_slice(),
                ":policy_decision_digest": digest(b"policy decision").as_bytes().as_slice(),
                ":catalogue_content_digest": digest(b"catalogue content").as_bytes().as_slice(),
                ":catalogue_decision_digest": digest(b"catalogue decision").as_bytes().as_slice(),
                ":capability_report_digest": case.capability_report_digest.as_bytes().as_slice(),
                ":driver_digest": digest(b"host driver context").as_bytes().as_slice(),
                ":evaluated_utc": ISSUED_AT_MS as i64,
                ":final_utc": (ISSUED_AT_MS + 1) as i64,
                ":observed_utc": (ISSUED_AT_MS - 1_000) as i64,
                ":replay_claim_id": case.replay_claim_id.as_bytes().as_slice(),
                ":replay_generation": case.replay_claimant_generation as i64,
                ":replay_binding_digest": case.replay_binding_digest.as_bytes().as_slice(),
                ":scope_id": case.scope_id.as_bytes().as_slice(),
                ":scope_generation": case.scope_generation as i64,
                ":provider_generation": provider_generation,
                ":comparison_digest": zero.as_slice(),
            },
        )?;
        reach_member_staged();
        Ok(())
    }

    fn stage_scope_delta(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
    ) -> rusqlite::Result<()> {
        let updated = transaction.execute(
            "UPDATE budget_scopes SET
                 held_cost_micro_units = held_cost_micro_units + ?2,
                 held_action_count = held_action_count + ?3,
                 held_egress_bytes = held_egress_bytes + ?4,
                 held_recovery_bytes = held_recovery_bytes + ?5
             WHERE scope_id = ?1
               AND held_cost_micro_units + ?2 <= total_cost_micro_units
               AND held_action_count + ?3 <= total_action_count
               AND held_egress_bytes + ?4 <= total_egress_bytes
               AND held_recovery_bytes + ?5 <= total_recovery_bytes",
            params![
                case.scope_id.as_bytes().as_slice(),
                case.requested[0] as i64,
                case.requested[1] as i64,
                case.requested[2] as i64,
                case.requested[3] as i64,
            ],
        )?;
        if updated != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        reach_member_staged();
        Ok(())
    }

    fn stage_reservation(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
        created_generation: i64,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            "INSERT INTO budget_reservations (
                 reservation_id, operation_id, attempt_id, plan_id, scope_id,
                 task_lease_digest, budget_generation, currency_code, price_table_id,
                 reserved_cost_micro_units, reserved_action_count, reserved_egress_bytes,
                 reserved_recovery_bytes, reservation_state, created_generation,
                 released_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       'HELD', ?14, NULL)",
            params![
                case.reservation_id,
                case.operation_id,
                case.attempt_id.as_bytes().as_slice(),
                case.plan_id.as_bytes().as_slice(),
                case.scope_id.as_bytes().as_slice(),
                case.task_lease_digest.as_bytes().as_slice(),
                case.scope_generation as i64,
                case.currency_code,
                case.price_table_id,
                case.requested[0] as i64,
                case.requested[1] as i64,
                case.requested[2] as i64,
                case.requested[3] as i64,
                created_generation,
            ],
        )?;
        reach_member_staged();
        Ok(())
    }

    fn stage_recovery(
        transaction: &Transaction<'_>,
        case: &SyntheticPreparationCaseV1,
    ) -> rusqlite::Result<()> {
        match case.recovery_mode {
            RecoveryClassV1::Compensation => {
                let publication = digest_parts(
                    b"publication",
                    &[
                        case.attempt_id.as_bytes(),
                        case.recovery_variant_digest.as_bytes(),
                    ],
                );
                let manifest = digest_parts(
                    b"manifest",
                    &[
                        case.recovery_variant_digest.as_bytes(),
                        publication.as_bytes(),
                    ],
                );
                transaction.execute(
                    "INSERT INTO preparation_recovery_evidence (
                         operation_id, evidence_version, recovery_mode, recovery_class,
                         atomicity, risk_level, target_reference_digest,
                         precondition_identity_digest, precondition_digest, precondition_length,
                         reserved_capacity, provider_profile_id, provider_profile_version,
                         provider_id, provider_generation, evidence_class, at_rest_profile_id,
                         capability_binding_digest, material_id, publication_attempt_id,
                         manifest_digest, material_digest, material_length, material_state,
                         retirement_id, retirement_manifest_digest, retirement_generation,
                         boot_binding_digest, instance_epoch, fencing_epoch
                     ) VALUES (
                         ?1, 1, 'COMPENSATION', 'COMPENSATION', ?2, ?3, ?4, ?5, ?6, ?7,
                         ?8, 'recovery-profile:synthetic-v1', 1,
                         'recovery-provider:synthetic-v1', 1, 'SYNTHETIC_CONFORMANCE',
                         'at-rest:synthetic-v1', ?9, ?10, ?11, ?12, ?6, ?7, 'PUBLISHED',
                         NULL, NULL, NULL, ?13, ?14, ?15
                     )",
                    params![
                        case.operation_id,
                        atomicity_text(case.atomicity),
                        risk_text(case.risk_level),
                        case.target_reference_digest.as_bytes().as_slice(),
                        case.precondition_identity_digest.as_bytes().as_slice(),
                        case.precondition_digest.as_bytes().as_slice(),
                        case.precondition_length as i64,
                        case.requested[3] as i64,
                        case.recovery_variant_digest.as_bytes().as_slice(),
                        case.recovery_variant_digest.as_bytes().as_slice(),
                        publication.as_bytes().as_slice(),
                        manifest.as_bytes().as_slice(),
                        case.boot_binding_digest.as_bytes().as_slice(),
                        case.instance_epoch as i64,
                        case.fencing_epoch as i64,
                    ],
                )?;
            }
            RecoveryClassV1::Irreversible => {
                transaction.execute(
                    "INSERT INTO preparation_recovery_evidence (
                         operation_id, evidence_version, recovery_mode, recovery_class,
                         atomicity, risk_level, target_reference_digest,
                         precondition_identity_digest, precondition_digest, precondition_length,
                         reserved_capacity, provider_profile_id, provider_profile_version,
                         provider_id, provider_generation, evidence_class, at_rest_profile_id,
                         capability_binding_digest, material_id, publication_attempt_id,
                         manifest_digest, material_digest, material_length, material_state,
                         retirement_id, retirement_manifest_digest, retirement_generation,
                         boot_binding_digest, instance_epoch, fencing_epoch
                     ) VALUES (
                         ?1, 1, 'IRREVERSIBLE', 'IRREVERSIBLE', ?2, ?3, ?4, ?5, ?6, ?7,
                         ?8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                         NULL, NULL, NULL, NULL, NULL, NULL, ?9, ?10, ?11
                     )",
                    params![
                        case.operation_id,
                        atomicity_text(case.atomicity),
                        risk_text(case.risk_level),
                        case.target_reference_digest.as_bytes().as_slice(),
                        case.precondition_identity_digest.as_bytes().as_slice(),
                        case.precondition_digest.as_bytes().as_slice(),
                        case.precondition_length as i64,
                        case.requested[3] as i64,
                        case.boot_binding_digest.as_bytes().as_slice(),
                        case.instance_epoch as i64,
                        case.fencing_epoch as i64,
                    ],
                )?;
            }
        }
        reach_member_staged();
        Ok(())
    }

    fn finalize_all_synthetic_comparison_digests_v1(
        transaction: &Transaction<'_>,
    ) -> rusqlite::Result<()> {
        let operation_ids = {
            let mut statement = transaction.prepare(
                "SELECT operation_id FROM preparation_comparisons ORDER BY operation_id",
            )?;
            let operation_ids = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            operation_ids
        };
        for operation_id in operation_ids {
            let digest = immutable_comparison_digest_for_operation_v1(transaction, &operation_id)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let updated = transaction.execute(
                "UPDATE preparation_comparisons SET comparison_digest = ?1
                 WHERE operation_id = ?2",
                params![digest.as_slice(), operation_id],
            )?;
            if updated != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        Ok(())
    }

    fn verify_synthetic_store_v1(connection: &Connection) -> bool {
        let quick_check = connection
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .is_ok_and(|value| value == "ok");
        let foreign_keys_clean = connection
            .prepare("PRAGMA foreign_key_check")
            .and_then(|mut statement| statement.exists([]))
            .is_ok_and(|has_rows| !has_rows);
        let joins_complete = connection
            .query_row(
                "SELECT NOT EXISTS (
                     SELECT 1 FROM prepared_operations AS operation
                     LEFT JOIN operation_transitions AS transition
                       ON transition.operation_id = operation.operation_id
                     LEFT JOIN preparation_comparisons AS comparison
                       ON comparison.operation_id = operation.operation_id
                     LEFT JOIN budget_reservations AS reservation
                       ON reservation.operation_id = operation.operation_id
                     LEFT JOIN preparation_recovery_evidence AS recovery
                       ON recovery.operation_id = operation.operation_id
                     LEFT JOIN preparation_events AS event
                       ON event.event_id = operation.current_event_id
                     WHERE transition.operation_id IS NULL OR comparison.operation_id IS NULL
                        OR reservation.operation_id IS NULL OR recovery.operation_id IS NULL
                        OR event.event_id IS NULL
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false);
        quick_check
            && foreign_keys_clean
            && joins_complete
            && all_comparison_digests_are_exact(connection)
    }

    fn all_comparison_digests_are_exact(connection: &Connection) -> bool {
        verify_persisted_comparison_digests_v1(connection).is_ok()
    }

    fn commit_receipt(
        case: &SyntheticPreparationCaseV1,
        store_generation: u64,
        state_generation: u64,
        event_generation: u64,
        reservation_generation: u64,
    ) -> Option<PreparationCommitReceiptV1> {
        let reservation = BudgetReservationReceiptV1::try_new(BudgetReservationReceiptInputV1 {
            contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
            state: BudgetReservationStateV1::Held,
            reservation_generation,
        })
        .ok()?;
        PreparationCommitReceiptV1::try_new(PreparationCommitReceiptInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            attempt_id: case.attempt_id,
            store_generation,
            operation_state_generation: state_generation,
            transition_generation: state_generation,
            event_generation,
            budget_reservation: reservation,
        })
        .ok()
    }

    fn uncertain(case: &SyntheticPreparationCaseV1) -> PreparationCommitOutcomeV1 {
        match PreparationCommitUncertainV1::try_new(
            PREPARATION_STORE_CONTRACT_VERSION_V1,
            case.attempt_id,
        ) {
            Ok(token) => PreparationCommitOutcomeV1::Uncertain {
                token,
                in_flight: (),
            },
            Err(_) => PreparationCommitOutcomeV1::Unclassified,
        }
    }

    fn rollback_after(
        _transaction: &Transaction<'_>,
        mode: SyntheticCommitModeV1,
        member: usize,
    ) -> bool {
        matches!(mode, SyntheticCommitModeV1::ConfirmedRollbackAfterMember(value) if value == member)
    }

    fn rollback_member(transaction: Transaction<'_>) -> PreparationCommitOutcomeV1 {
        if transaction.rollback().is_ok() {
            PreparationCommitOutcomeV1::ConfirmedRollback
        } else {
            PreparationCommitOutcomeV1::Unclassified
        }
    }

    fn recovery_mode_text(mode: RecoveryClassV1) -> &'static str {
        match mode {
            RecoveryClassV1::Compensation => "COMPENSATION",
            RecoveryClassV1::Irreversible => "IRREVERSIBLE",
        }
    }

    fn atomicity_text(value: AtomicityV1) -> &'static str {
        match value {
            AtomicityV1::AtomicReplace => "ATOMIC_REPLACE",
            AtomicityV1::NonAtomic => "NON_ATOMIC",
        }
    }

    fn risk_text(value: RiskLevelV1) -> &'static str {
        match value {
            RiskLevelV1::L0 => "L0",
            RiskLevelV1::L1 => "L1",
            RiskLevelV1::L2 => "L2",
        }
    }

    fn digest(value: &[u8]) -> Sha256Digest {
        Sha256Digest::digest(value)
    }

    fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HELIXOS\0SYNTHETIC-PREPARATION\0V1\0");
        bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        bytes.extend_from_slice(domain);
        for part in parts {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        Sha256Digest::digest(&bytes)
    }

    #[inline]
    fn reach_member_staged() {
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitMemberStaged,
        );
    }
}
