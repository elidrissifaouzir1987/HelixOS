use std::fmt;

pub type Result<T> = std::result::Result<T, ContractError>;

/// Closed, payload-free failures for the dispatch wire boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    AdapterRootBindingMismatch,
    CanonicalizationFailed,
    DestinationBindingMismatch,
    DigestMismatch,
    DuplicateMember,
    GrantBindingMismatch,
    GrantLifetimeExceeded,
    HistoricalKeyNotAuthority,
    InvalidDecisionShape,
    InvalidEncoding,
    InvalidField,
    InvalidPublicKey,
    MalformedJson,
    MissingOuterField,
    MissingRequiredField,
    NonCanonicalWire,
    OperationBindingMismatch,
    PreReceivedCodeNotReceipt,
    SignatureInvalid,
    SigningFailed,
    SupervisorEpochBindingMismatch,
    UnknownDecision,
    UnknownField,
    UnknownKey,
    UnsupportedDigestAlgorithm,
    UnsupportedProtocol,
    UnsupportedSchema,
    UnsupportedSignatureAlgorithm,
    WireTooLarge,
    WrongKeyPurpose,
}

impl ContractError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AdapterRootBindingMismatch => "ADAPTER_ROOT_BINDING_MISMATCH",
            Self::CanonicalizationFailed => "CANONICALIZATION_FAILED",
            Self::DestinationBindingMismatch => "DESTINATION_BINDING_MISMATCH",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::DuplicateMember => "DUPLICATE_MEMBER",
            Self::GrantBindingMismatch => "GRANT_BINDING_MISMATCH",
            Self::GrantLifetimeExceeded => "GRANT_LIFETIME_EXCEEDED",
            Self::HistoricalKeyNotAuthority => "HISTORICAL_KEY_NOT_AUTHORITY",
            Self::InvalidDecisionShape => "INVALID_DECISION_SHAPE",
            Self::InvalidEncoding => "INVALID_ENCODING",
            Self::InvalidField => "INVALID_FIELD",
            Self::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            Self::MalformedJson => "MALFORMED_JSON",
            Self::MissingOuterField => "MISSING_OUTER_FIELD",
            Self::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Self::NonCanonicalWire => "NON_CANONICAL_WIRE",
            Self::OperationBindingMismatch => "OPERATION_BINDING_MISMATCH",
            Self::PreReceivedCodeNotReceipt => "PRE_RECEIVED_CODE_NOT_RECEIPT",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::SigningFailed => "SIGNING_FAILED",
            Self::SupervisorEpochBindingMismatch => "SUPERVISOR_EPOCH_BINDING_MISMATCH",
            Self::UnknownDecision => "UNKNOWN_DECISION",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::UnsupportedDigestAlgorithm => "UNSUPPORTED_DIGEST_ALGORITHM",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            Self::UnsupportedSchema => "UNSUPPORTED_SCHEMA",
            Self::UnsupportedSignatureAlgorithm => "UNSUPPORTED_SIGNATURE_ALGORITHM",
            Self::WireTooLarge => "WIRE_TOO_LARGE",
            Self::WrongKeyPurpose => "WRONG_KEY_PURPOSE",
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ContractError {}
