use thiserror::Error;

pub type Result<T> = std::result::Result<T, ContractError>;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("invalid contract field `{field}`: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },

    #[error("invalid {kind} encoding")]
    InvalidEncoding { kind: &'static str },

    #[error("contract canonicalization failed")]
    Canonicalization,

    #[error("malformed contract JSON at line {line}, column {column}")]
    MalformedJson { line: usize, column: usize },

    #[error("contract wire payload exceeds {maximum} bytes")]
    WireTooLarge { maximum: usize },

    #[error("contract wire payload is not canonical RFC 8785 JSON")]
    NonCanonicalWire,

    #[error("unsupported contract schema")]
    UnsupportedSchema,

    #[error("unsupported {kind} algorithm")]
    UnsupportedAlgorithm { kind: &'static str },

    #[error("unsupported contract intent")]
    UnsupportedIntent,

    #[error("plan identifier does not match protected content")]
    PlanIdMismatch,

    #[error("signer key identifier does not match protected content")]
    SignerKeyMismatch,

    #[error("plan signing failed")]
    SigningFailed,

    #[error("verification key is unknown or revoked")]
    UnknownKey,

    #[error("verification key is malformed")]
    InvalidPublicKey,

    #[error("plan signature is invalid")]
    SignatureInvalid,
}

impl From<serde_json::Error> for ContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::MalformedJson {
            line: error.line(),
            column: error.column(),
        }
    }
}

impl ContractError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidField { .. } => "INVALID_FIELD",
            Self::InvalidEncoding { .. } => "INVALID_ENCODING",
            Self::Canonicalization => "CANONICALIZATION_FAILED",
            Self::MalformedJson { .. } => "MALFORMED_JSON",
            Self::WireTooLarge { .. } => "WIRE_TOO_LARGE",
            Self::NonCanonicalWire => "NON_CANONICAL_WIRE",
            Self::UnsupportedSchema => "UNSUPPORTED_SCHEMA",
            Self::UnsupportedAlgorithm { .. } => "UNSUPPORTED_ALGORITHM",
            Self::UnsupportedIntent => "UNSUPPORTED_INTENT",
            Self::PlanIdMismatch => "PLAN_ID_MISMATCH",
            Self::SignerKeyMismatch => "SIGNER_KEY_MISMATCH",
            Self::SigningFailed => "SIGNING_FAILED",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
        }
    }

    pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidField { field, reason }
    }
}
