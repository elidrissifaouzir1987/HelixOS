use crate::{ContractError, Result};
use serde::Serialize;

pub(crate) fn to_jcs_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ContractError::Canonicalization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc_8785_property_order_uses_utf16_code_units() {
        let value = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{0080}": "Control",
            "ö": "Latin Small Letter O With Diaeresis"
        });
        let output = String::from_utf8(to_jcs_vec(&value).expect("JCS")).expect("UTF-8");
        assert_eq!(
            output,
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn canonicalization_is_idempotent_for_json_values() {
        let value = json!({"z": [true, false, null], "a": {"b": "text"}});
        let first = to_jcs_vec(&value).expect("first");
        let parsed: serde_json::Value = serde_json::from_slice(&first).expect("parse");
        assert_eq!(first, to_jcs_vec(&parsed).expect("second"));
    }
}
