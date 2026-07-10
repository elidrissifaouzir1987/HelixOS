use crate::digest::{decode_lower_hex, encode_lower_hex};
use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const MAX_SAFE_U64: u64 = 9_007_199_254_740_991;
pub const MAX_IDENTIFIER_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeU64(u64);

impl SafeU64 {
    pub fn new(value: u64) -> Result<Self> {
        if value > MAX_SAFE_U64 {
            return Err(ContractError::invalid(
                "integer",
                "outside the RFC 8785/I-JSON exact range",
            ));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SafeU64 {
    type Error = ContractError;

    fn try_from(value: u64) -> Result<Self> {
        Self::new(value)
    }
}

impl Serialize for SafeU64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SafeU64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SafeVisitor;

        impl de::Visitor<'_> for SafeVisitor {
            type Value = SafeU64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative I-JSON safe integer")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                SafeU64::new(value).map_err(E::custom)
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = u64::try_from(value).map_err(|_| E::custom("negative integer"))?;
                self.visit_u64(value)
            }
        }

        deserializer.deserialize_any(SafeVisitor)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>, maximum: usize) -> Result<Self> {
        let value = value.into();
        if maximum == 0 || maximum > MAX_IDENTIFIER_LEN {
            return Err(ContractError::invalid(
                "identifier",
                "invalid configured bound",
            ));
        }
        if value.is_empty() || value.len() > maximum {
            return Err(ContractError::invalid(
                "identifier",
                "empty or exceeds its length bound",
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(ContractError::invalid(
                "identifier",
                "contains a non-portable character",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identifier")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw, MAX_IDENTIFIER_LEN).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce128([u8; 16]);

impl Nonce128 {
    pub const HEX_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != Self::HEX_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidEncoding { kind: "nonce" });
        }
        let mut bytes = [0_u8; 16];
        decode_lower_hex(value.as_bytes(), &mut bytes)
            .ok_or(ContractError::InvalidEncoding { kind: "nonce" })?;
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        encode_lower_hex(&self.0)
    }
}

impl fmt::Debug for Nonce128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nonce128(<redacted>)")
    }
}

impl Serialize for Nonce128 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Nonce128 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse_hex(&raw).map_err(de::Error::custom)
    }
}
