//! Closed outcome vocabulary for authoritative task-authority mutations.
//!
//! Runtime mutation and readback classifications deliberately do not expose
//! adapter-native errors or retained payloads through [`fmt::Debug`]. The durable
//! outcome code is kept separate because only retained outcomes belong in the
//! authority-attempt ledger.

use std::fmt;

/// Outcome codes that may be retained in the authoritative attempt ledger.
#[derive(PartialEq, Eq)]
pub enum AuthorityRetainedOutcomeCodeV1 {
    CommittedRetained,
    ConflictRetained,
    RestorePending,
}

impl AuthorityRetainedOutcomeCodeV1 {
    /// Returns the stable SQL vocabulary used by the durable store schema.
    pub const fn sql_code_v1(&self) -> &'static str {
        match self {
            Self::CommittedRetained => "COMMITTED_RETAINED",
            Self::ConflictRetained => "CONFLICT_RETAINED",
            Self::RestorePending => "RESTORE_PENDING",
        }
    }
}

impl fmt::Debug for AuthorityRetainedOutcomeCodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::CommittedRetained => "CommittedRetained",
            Self::ConflictRetained => "ConflictRetained",
            Self::RestorePending => "RestorePending",
        };
        write!(formatter, "AuthorityRetainedOutcomeCodeV1::{variant}")
    }
}

/// Closed result of one authoritative mutation attempt.
///
/// `UncertainReadbackRequired` transfers an opaque readback capability to the
/// caller; it does not authorize retrying the mutation.
pub enum AuthorityMutationOutcomeV1<R, U> {
    CommittedRetained(R),
    DeniedDefinite,
    ConflictRetained,
    UncertainReadbackRequired(U),
    AmbiguousReconciliationRequired,
    Unavailable,
}

impl<R, U> fmt::Debug for AuthorityMutationOutcomeV1<R, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::CommittedRetained(_) => "CommittedRetained(..)",
            Self::DeniedDefinite => "DeniedDefinite",
            Self::ConflictRetained => "ConflictRetained",
            Self::UncertainReadbackRequired(_) => "UncertainReadbackRequired(..)",
            Self::AmbiguousReconciliationRequired => "AmbiguousReconciliationRequired",
            Self::Unavailable => "Unavailable",
        };
        write!(formatter, "AuthorityMutationOutcomeV1::{variant}")
    }
}

/// Closed classification returned by the single exact readback after uncertainty.
pub enum AuthorityReadbackOutcomeV1<R> {
    CommittedRetained(R),
    ConflictRetained,
    DeniedDefinite,
    AmbiguousReconciliationRequired,
}

impl<R> fmt::Debug for AuthorityReadbackOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::CommittedRetained(_) => "CommittedRetained(..)",
            Self::ConflictRetained => "ConflictRetained",
            Self::DeniedDefinite => "DeniedDefinite",
            Self::AmbiguousReconciliationRequired => "AmbiguousReconciliationRequired",
        };
        write!(formatter, "AuthorityReadbackOutcomeV1::{variant}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityMutationOutcomeV1, AuthorityReadbackOutcomeV1, AuthorityRetainedOutcomeCodeV1,
    };

    #[test]
    fn retained_outcome_codes_match_the_stable_sql_vocabulary() {
        assert_eq!(
            AuthorityRetainedOutcomeCodeV1::CommittedRetained.sql_code_v1(),
            "COMMITTED_RETAINED"
        );
        assert_eq!(
            AuthorityRetainedOutcomeCodeV1::ConflictRetained.sql_code_v1(),
            "CONFLICT_RETAINED"
        );
        assert_eq!(
            AuthorityRetainedOutcomeCodeV1::RestorePending.sql_code_v1(),
            "RESTORE_PENDING"
        );
    }

    #[test]
    fn mutation_debug_redacts_committed_and_uncertain_payloads() {
        const SECRET: &str = "candidate-generated-secret";

        let committed = AuthorityMutationOutcomeV1::<&str, &str>::CommittedRetained(SECRET);
        let uncertain = AuthorityMutationOutcomeV1::<&str, &str>::UncertainReadbackRequired(SECRET);

        let committed_debug = format!("{committed:?}");
        let uncertain_debug = format!("{uncertain:?}");
        assert_eq!(
            committed_debug,
            "AuthorityMutationOutcomeV1::CommittedRetained(..)"
        );
        assert_eq!(
            uncertain_debug,
            "AuthorityMutationOutcomeV1::UncertainReadbackRequired(..)"
        );
        assert!(!committed_debug.contains(SECRET));
        assert!(!uncertain_debug.contains(SECRET));
    }

    #[test]
    fn readback_debug_redacts_retained_payloads() {
        const SECRET: &str = "retained-authority-secret";
        let outcome = AuthorityReadbackOutcomeV1::CommittedRetained(SECRET);

        let debug = format!("{outcome:?}");
        assert_eq!(debug, "AuthorityReadbackOutcomeV1::CommittedRetained(..)");
        assert!(!debug.contains(SECRET));
    }

    #[test]
    fn every_closed_runtime_classification_has_a_fixed_payload_free_debug_name() {
        let mutation = [
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::CommittedRetained("secret")
            ),
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::DeniedDefinite
            ),
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::ConflictRetained
            ),
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::UncertainReadbackRequired("secret")
            ),
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::AmbiguousReconciliationRequired
            ),
            format!(
                "{:?}",
                AuthorityMutationOutcomeV1::<&str, &str>::Unavailable
            ),
        ];
        assert_eq!(
            mutation,
            [
                "AuthorityMutationOutcomeV1::CommittedRetained(..)",
                "AuthorityMutationOutcomeV1::DeniedDefinite",
                "AuthorityMutationOutcomeV1::ConflictRetained",
                "AuthorityMutationOutcomeV1::UncertainReadbackRequired(..)",
                "AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired",
                "AuthorityMutationOutcomeV1::Unavailable",
            ]
        );

        let readback = [
            format!(
                "{:?}",
                AuthorityReadbackOutcomeV1::CommittedRetained("secret")
            ),
            format!("{:?}", AuthorityReadbackOutcomeV1::<&str>::ConflictRetained),
            format!("{:?}", AuthorityReadbackOutcomeV1::<&str>::DeniedDefinite),
            format!(
                "{:?}",
                AuthorityReadbackOutcomeV1::<&str>::AmbiguousReconciliationRequired
            ),
        ];
        assert_eq!(
            readback,
            [
                "AuthorityReadbackOutcomeV1::CommittedRetained(..)",
                "AuthorityReadbackOutcomeV1::ConflictRetained",
                "AuthorityReadbackOutcomeV1::DeniedDefinite",
                "AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired",
            ]
        );
        assert!(mutation
            .iter()
            .chain(readback.iter())
            .all(|rendered| !rendered.contains("secret")));
    }
}
