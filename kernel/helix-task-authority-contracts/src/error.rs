use std::fmt;

pub type Result<T> = std::result::Result<T, ContractError>;

/// Closed, payload-free failures for the signed task-authority wire boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    CanonicalizationFailed,
    DigestMismatch,
    DuplicateMember,
    HistoricalKeyNotAuthority,
    InvalidEncoding,
    InvalidField,
    InvalidPublicKey,
    MalformedJson,
    MissingOuterField,
    MissingRequiredField,
    NonCanonicalWire,
    SignatureInvalid,
    SigningFailed,
    UnknownField,
    UnknownKey,
    UnsupportedDigestAlgorithm,
    UnsupportedSchema,
    UnsupportedSignatureAlgorithm,
    WireTooLarge,
    WrongKeyPurpose,
}

impl ContractError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CanonicalizationFailed => "CANONICALIZATION_FAILED",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::DuplicateMember => "DUPLICATE_MEMBER",
            Self::HistoricalKeyNotAuthority => "HISTORICAL_KEY_NOT_AUTHORITY",
            Self::InvalidEncoding => "INVALID_ENCODING",
            Self::InvalidField => "INVALID_FIELD",
            Self::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            Self::MalformedJson => "MALFORMED_JSON",
            Self::MissingOuterField => "MISSING_OUTER_FIELD",
            Self::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Self::NonCanonicalWire => "NON_CANONICAL_WIRE",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::SigningFailed => "SIGNING_FAILED",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::UnsupportedDigestAlgorithm => "UNSUPPORTED_DIGEST_ALGORITHM",
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

#[cfg(test)]
mod tests {
    use super::*;

    const ERRORS: &[ContractError] = &[
        ContractError::CanonicalizationFailed,
        ContractError::DigestMismatch,
        ContractError::DuplicateMember,
        ContractError::HistoricalKeyNotAuthority,
        ContractError::InvalidEncoding,
        ContractError::InvalidField,
        ContractError::InvalidPublicKey,
        ContractError::MalformedJson,
        ContractError::MissingOuterField,
        ContractError::MissingRequiredField,
        ContractError::NonCanonicalWire,
        ContractError::SignatureInvalid,
        ContractError::SigningFailed,
        ContractError::UnknownField,
        ContractError::UnknownKey,
        ContractError::UnsupportedDigestAlgorithm,
        ContractError::UnsupportedSchema,
        ContractError::UnsupportedSignatureAlgorithm,
        ContractError::WireTooLarge,
        ContractError::WrongKeyPurpose,
    ];

    #[test]
    fn codes_are_stable_unique_and_payload_free() {
        for (index, error) in ERRORS.iter().enumerate() {
            let code = error.code();
            assert!(!code.is_empty());
            assert!(code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_'));
            assert_eq!(error.to_string(), code);
            assert!(std::error::Error::source(error).is_none());
            assert!(!ERRORS[index + 1..]
                .iter()
                .any(|candidate| candidate.code() == code));
        }
    }
}
