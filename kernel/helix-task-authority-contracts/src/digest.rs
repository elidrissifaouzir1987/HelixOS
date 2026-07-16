use crate::{ContractError, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const BYTE_LEN: usize = 32;
    pub const HEX_LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn parse_hex(text: &str) -> Result<Self> {
        if text.len() != Self::HEX_LEN
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidEncoding);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(Self::HEX_LEN);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

fn nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ContractError::InvalidEncoding),
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sha256Digest")
            .finish_non_exhaustive()
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        Self::parse_hex(&text).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_known_sha256_vector() {
        let digest = Sha256Digest::digest(b"abc");

        assert_eq!(
            digest.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn round_trips_exact_lowercase_hex_and_bytes() {
        let bytes = [0xab; Sha256Digest::BYTE_LEN];
        let digest = Sha256Digest::from_bytes(bytes);
        let hex = "ab".repeat(Sha256Digest::BYTE_LEN);

        assert_eq!(digest.as_bytes(), &bytes);
        assert_eq!(digest.to_hex(), hex);
        assert_eq!(
            Sha256Digest::parse_hex(&hex).expect("lowercase digest must parse"),
            digest
        );
    }

    #[test]
    fn rejects_noncanonical_or_malformed_hex() {
        let valid = Sha256Digest::digest(b"abc").to_hex();
        for invalid in [
            valid.to_uppercase(),
            format!("0x{valid}"),
            valid[..valid.len() - 1].to_owned(),
            format!("{valid}0"),
            format!("g{}", &valid[1..]),
            "é".repeat(Sha256Digest::BYTE_LEN),
        ] {
            assert_eq!(
                Sha256Digest::parse_hex(&invalid),
                Err(ContractError::InvalidEncoding)
            );
        }
    }

    #[test]
    fn serde_uses_only_the_canonical_hex_string() {
        let digest = Sha256Digest::digest(b"{}");
        let encoded = serde_json::to_string(&digest).expect("digest must serialize");

        assert_eq!(
            encoded,
            "\"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\""
        );
        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&encoded).expect("digest must deserialize"),
            digest
        );
    }

    #[test]
    fn debug_is_strictly_opaque() {
        let digest = Sha256Digest::digest(b"sensitive protected bytes");
        let rendered = format!("{digest:?}");

        assert_eq!(rendered, "Sha256Digest { .. }");
        assert!(!rendered.contains(&digest.to_hex()));
    }
}
