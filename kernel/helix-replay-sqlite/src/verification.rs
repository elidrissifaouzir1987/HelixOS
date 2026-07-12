//! Query-only verification of the exact permanent replay row carried by eligibility.

use crate::claim::{
    lookup_by_claim_id_connection, lookup_by_nonce_connection, lookup_by_operation_connection,
    StoredClaimV1,
};
use crate::clock::remaining_monotonic_ms;
use crate::connection::{map_sqlite_error, open_existing_query_only};
use crate::error::InternalStoreError;
use crate::root_safety::acquire_checked_live_root_lease;
use crate::schema::verify_lightweight;
use crate::{ReplayMonotonicClockV1, SqliteReplayClaimantV1};
use helix_plan_eligibility::{
    ReplayClaimVerificationV1, ReplayClaimVerificationViewV1, ReplayClaimVerifierV1,
};
use rusqlite::TransactionBehavior;
use std::sync::atomic::Ordering;

impl<C: ReplayMonotonicClockV1> ReplayClaimVerifierV1 for SqliteReplayClaimantV1<C> {
    fn verify_exact_claim(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        if !self.healthy.load(Ordering::Acquire) {
            return ReplayClaimVerificationV1::Unhealthy;
        }

        match self.verify_exact_claim_query_only(view, deadline_monotonic_ms) {
            Ok(verification) => verification,
            Err(error) => self.classify_verification_error(error),
        }
    }
}

impl<C: ReplayMonotonicClockV1> SqliteReplayClaimantV1<C> {
    fn verify_exact_claim_query_only(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayClaimVerificationV1, InternalStoreError> {
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;
        let mut connection =
            open_existing_query_only(&self.config, &self.clock, deadline_monotonic_ms)?;
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;

        let _root_lease = acquire_checked_live_root_lease(
            self.config.root(),
            self.config.maximum_busy_wait_ms(),
            &self.clock,
            deadline_monotonic_ms,
        )?;
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
        verify_lightweight(&transaction, self.schema_cookie)?;
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;

        let (instance_epoch, nonce) = view.nonce_key();
        let nonce_claim =
            lookup_by_nonce_connection(&transaction, instance_epoch, nonce.as_bytes())?;
        let operation_claim = lookup_by_operation_connection(&transaction, view.operation_id())?;
        let claim_id_claim = lookup_by_claim_id_connection(&transaction, view.claim_id())?;
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;

        let verification = classify_exact_rows(
            nonce_claim.as_ref(),
            operation_claim.as_ref(),
            claim_id_claim.as_ref(),
            view,
        );
        transaction
            .rollback()
            .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
        remaining_monotonic_ms(&self.clock, deadline_monotonic_ms)?;
        Ok(verification)
    }

    fn classify_verification_error(&self, error: InternalStoreError) -> ReplayClaimVerificationV1 {
        if error.requires_unhealthy_latch()
            || matches!(error, InternalStoreError::DurabilityProfileUnavailable)
        {
            self.healthy.store(false, Ordering::Release);
            ReplayClaimVerificationV1::Unhealthy
        } else {
            ReplayClaimVerificationV1::Unavailable
        }
    }
}

fn classify_exact_rows(
    nonce_claim: Option<&StoredClaimV1>,
    operation_claim: Option<&StoredClaimV1>,
    claim_id_claim: Option<&StoredClaimV1>,
    view: &ReplayClaimVerificationViewV1<'_>,
) -> ReplayClaimVerificationV1 {
    match (nonce_claim, operation_claim, claim_id_claim) {
        (None, None, None) => ReplayClaimVerificationV1::Missing,
        (Some(nonce), Some(operation), Some(claim_id))
            if nonce == operation && nonce == claim_id && nonce.matches_verification_view(view) =>
        {
            ReplayClaimVerificationV1::Exact
        }
        _ => ReplayClaimVerificationV1::Conflict,
    }
}
