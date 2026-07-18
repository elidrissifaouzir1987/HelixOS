//! Closed portable current-versus-historical authority evaluation.
//!
//! These values classify already captured trust/revocation observations. They do not
//! create authority; the SQLite adapter must recheck the same facts under its writer
//! or projection guard before any positive commit.

use helix_task_authority_contracts::VerificationKeyStatusV1;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityCurrentnessV1 {
    Current,
    SignerHistorical,
    SignerRevoked,
    SourceRevoked,
    AncestorRevoked,
    DecisionRevoked,
}

impl AuthorityCurrentnessV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Current => "AUTHORITY_CURRENT",
            Self::SignerHistorical => "AUTHORITY_SIGNER_HISTORICAL",
            Self::SignerRevoked => "AUTHORITY_SIGNER_REVOKED",
            Self::SourceRevoked => "AUTHORITY_SOURCE_REVOKED",
            Self::AncestorRevoked => "AUTHORITY_ANCESTOR_REVOKED",
            Self::DecisionRevoked => "AUTHORITY_DECISION_REVOKED",
        }
    }

    pub const fn is_current_v1(self) -> bool {
        matches!(self, Self::Current)
    }
}

impl fmt::Debug for AuthorityCurrentnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

/// Applies the fixed denial precedence used by current-authority consumers.
pub const fn evaluate_authority_currentness_v1(
    signer_status: VerificationKeyStatusV1,
    signer_revoked: bool,
    source_revoked: bool,
    ancestor_revoked: bool,
    decision_revoked: bool,
) -> AuthorityCurrentnessV1 {
    if signer_revoked {
        AuthorityCurrentnessV1::SignerRevoked
    } else if !matches!(signer_status, VerificationKeyStatusV1::Current) {
        AuthorityCurrentnessV1::SignerHistorical
    } else if source_revoked {
        AuthorityCurrentnessV1::SourceRevoked
    } else if ancestor_revoked {
        AuthorityCurrentnessV1::AncestorRevoked
    } else if decision_revoked {
        AuthorityCurrentnessV1::DecisionRevoked
    } else {
        AuthorityCurrentnessV1::Current
    }
}
