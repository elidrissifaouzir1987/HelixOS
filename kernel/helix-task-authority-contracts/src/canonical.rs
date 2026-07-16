use crate::{ContractError, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

pub(crate) fn decode_canonical_value(wire: &[u8], maximum: usize) -> Result<Value> {
    if wire.len() > maximum {
        return Err(ContractError::WireTooLarge);
    }
    if wire.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ContractError::NonCanonicalWire);
    }
    let value = serde_json::from_slice::<UniqueJsonValue>(wire)
        .map_err(|error| {
            if error.to_string().contains("duplicate JSON member") {
                ContractError::DuplicateMember
            } else {
                ContractError::MalformedJson
            }
        })?
        .0;
    if to_jcs_vec(&value)? != wire {
        return Err(ContractError::NonCanonicalWire);
    }
    Ok(value)
}

pub(crate) fn to_jcs_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ContractError::CanonicalizationFailed)
}

pub(crate) fn require_closed_object(value: &Value, required: &[&str], outer: bool) -> Result<()> {
    let object = value.as_object().ok_or(ContractError::InvalidField)?;
    if required.iter().any(|name| !object.contains_key(*name)) {
        return Err(if outer {
            ContractError::MissingOuterField
        } else {
            ContractError::MissingRequiredField
        });
    }
    if object.len() != required.len()
        || object.keys().any(|name| !required.contains(&name.as_str()))
    {
        return Err(ContractError::UnknownField);
    }
    Ok(())
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor).map(Self)
    }
}

struct UniqueSeed;

impl<'de> DeserializeSeed<'de> for UniqueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value with unique object members")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = BTreeSet::new();
        let mut values = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name.clone()) {
                return Err(de::Error::custom("duplicate JSON member"));
            }
            values.insert(name, map.next_value_seed(UniqueSeed)?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::Error as _;
    use serde_json::json;

    const TEST_LIMIT: usize = 65_536;

    #[test]
    fn accepts_exact_canonical_json_and_is_idempotent() {
        let wire = br#"{"a":[true,null,3],"b":"text"}"#;

        let value = decode_canonical_value(wire, TEST_LIMIT).expect("canonical JSON must decode");

        assert_eq!(value, json!({"a": [true, null, 3], "b": "text"}));
        assert_eq!(
            to_jcs_vec(&value).expect("decoded JSON must canonicalize"),
            wire
        );
    }

    #[test]
    fn rejects_duplicate_decoded_member_names_at_every_depth() {
        for wire in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":1,"\u0061":2}"#.as_slice(),
            br#"{"nested":{"x":1,"x":2}}"#.as_slice(),
            br#"[{"x":1,"x":2}]"#.as_slice(),
        ] {
            assert_eq!(
                decode_canonical_value(wire, TEST_LIMIT),
                Err(ContractError::DuplicateMember)
            );
        }
    }

    #[test]
    fn rejects_noncanonical_bom_layout_escapes_and_numbers() {
        for wire in [
            b"\xef\xbb\xbf{}".as_slice(),
            b" {}".as_slice(),
            b"{}\n".as_slice(),
            br#"{"b":1,"a":2}"#.as_slice(),
            br#"{"a":"\u0061"}"#.as_slice(),
            br#"{"a":1.0}"#.as_slice(),
            br#"{"a":1e0}"#.as_slice(),
            br#"{"a":-0}"#.as_slice(),
        ] {
            assert_eq!(
                decode_canonical_value(wire, TEST_LIMIT),
                Err(ContractError::NonCanonicalWire)
            );
        }
    }

    #[test]
    fn rejects_malformed_or_trailing_json() {
        for wire in [
            b"".as_slice(),
            b"{".as_slice(),
            b"\xff".as_slice(),
            b"{}{}".as_slice(),
            br#""\ud800""#.as_slice(),
        ] {
            assert_eq!(
                decode_canonical_value(wire, TEST_LIMIT),
                Err(ContractError::MalformedJson)
            );
        }
    }

    #[test]
    fn checks_size_before_other_wire_properties() {
        let wire = serde_json_canonicalizer::to_vec(&"a".repeat(62))
            .expect("bounded string must canonicalize");
        assert_eq!(wire.len(), 64);
        assert!(decode_canonical_value(&wire, 64).is_ok());
        assert_eq!(
            decode_canonical_value(&wire, 63),
            Err(ContractError::WireTooLarge)
        );

        let bom = b"\xef\xbb\xbf{}";
        assert_eq!(
            decode_canonical_value(bom, bom.len() - 1),
            Err(ContractError::WireTooLarge)
        );
        assert_eq!(
            decode_canonical_value(bom, bom.len()),
            Err(ContractError::NonCanonicalWire)
        );
    }

    #[test]
    fn canonicalizer_uses_utf16_member_order() {
        let value = json!({"\u{e000}": 1, "\u{1f600}": 2});

        assert_eq!(
            to_jcs_vec(&value).expect("object must canonicalize"),
            "{\"😀\":2,\"\":1}".as_bytes()
        );
    }

    #[test]
    fn closed_object_requires_exact_member_inventory() {
        let value = json!({"a": 1, "b": 2});
        assert_eq!(require_closed_object(&value, &["a", "b"], true), Ok(()));
        assert_eq!(
            require_closed_object(&value, &["a", "missing"], true),
            Err(ContractError::MissingOuterField)
        );
        assert_eq!(
            require_closed_object(&value, &["a", "missing"], false),
            Err(ContractError::MissingRequiredField)
        );
        assert_eq!(
            require_closed_object(&value, &["a"], false),
            Err(ContractError::UnknownField)
        );
        assert_eq!(
            require_closed_object(&json!([]), &[], false),
            Err(ContractError::InvalidField)
        );
    }

    #[test]
    fn serializer_failures_are_payload_free() {
        struct FailingValue;

        impl Serialize for FailingValue {
            fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(S::Error::custom("private serializer detail"))
            }
        }

        assert_eq!(
            to_jcs_vec(&FailingValue),
            Err(ContractError::CanonicalizationFailed)
        );
    }
}
