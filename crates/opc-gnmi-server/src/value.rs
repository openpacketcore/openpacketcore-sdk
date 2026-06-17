//! Bounded gNMI TypedValue normalization.

use serde_json::Value;

use opc_mgmt_limits::MgmtLimits;

use crate::{Encoding, GnmiError};

/// Proto-free representation of the supported gNMI `TypedValue` variants.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    /// `json_ietf_val` bytes.
    JsonIetf(Vec<u8>),
    /// `json_val` bytes.
    Json(Vec<u8>),
    /// `string_val`.
    String(String),
    /// `bool_val`.
    Bool(bool),
    /// `int_val`.
    Int(i64),
    /// `uint_val`.
    Uint(u64),
    /// `float_val`.
    Float(f32),
    /// `double_val`.
    Double(f64),
    /// `leaflist_val` / nested scalar values are intentionally deferred.
    LeafList,
    /// `bytes_val` is not a schema-safe global encoding yet.
    Bytes(Vec<u8>),
    /// `ascii_val` is not a schema-safe global encoding yet.
    Ascii(String),
    /// `proto_bytes` is not implemented until per-model protobuf descriptors
    /// exist.
    Proto(Vec<u8>),
}

/// Normalized RFC 7951 JSON payload ready for generated model decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedValue {
    encoding: Encoding,
    json: String,
}

impl NormalizedValue {
    /// Builds a normalized value after validating JSON syntax and bounds.
    pub fn new(
        encoding: Encoding,
        json: impl Into<String>,
        limits: &MgmtLimits,
    ) -> Result<Self, GnmiError> {
        let json = json.into();
        limits
            .check_value_bytes(json.len())
            .map_err(GnmiError::from_limits)?;
        let parsed: Value = serde_json::from_str(&json)
            .map_err(|_| GnmiError::invalid("gNMI value is not valid JSON"))?;
        let compact = serde_json::to_string(&parsed)
            .map_err(|_| GnmiError::invalid("gNMI value is not valid JSON"))?;
        limits
            .check_value_bytes(compact.len())
            .map_err(GnmiError::from_limits)?;
        Ok(Self {
            encoding,
            json: compact,
        })
    }

    /// Encoding that supplied the value.
    pub const fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Compact RFC 7951 JSON string.
    pub fn json(&self) -> &str {
        &self.json
    }
}

/// Normalizes a gNMI `TypedValue` into RFC 7951 JSON.
///
/// This validates syntax and bounds only. Schema-specific semantic decoding is
/// still owned by generated config code / `GnmiPatchApplicator`.
pub fn normalize_typed_value(
    value: &TypedValue,
    limits: &MgmtLimits,
) -> Result<NormalizedValue, GnmiError> {
    match value {
        TypedValue::JsonIetf(bytes) => {
            let text = bytes_to_utf8(bytes)?;
            NormalizedValue::new(Encoding::JsonIetf, text, limits)
        }
        TypedValue::Json(bytes) => {
            let text = bytes_to_utf8(bytes)?;
            NormalizedValue::new(Encoding::Json, text, limits)
        }
        TypedValue::String(value) => {
            scalar_to_normalized(Encoding::JsonIetf, Value::String(value.clone()), limits)
        }
        TypedValue::Bool(value) => {
            scalar_to_normalized(Encoding::JsonIetf, Value::Bool(*value), limits)
        }
        TypedValue::Int(value) => scalar_to_normalized(
            Encoding::JsonIetf,
            Value::Number(serde_json::Number::from(*value)),
            limits,
        ),
        TypedValue::Uint(value) => scalar_to_normalized(
            Encoding::JsonIetf,
            Value::Number(serde_json::Number::from(*value)),
            limits,
        ),
        TypedValue::Float(value) => finite_float_to_normalized(*value as f64, limits),
        TypedValue::Double(value) => finite_float_to_normalized(*value, limits),
        TypedValue::LeafList => Err(GnmiError::unimplemented(
            "gNMI leaf-list TypedValue normalization is not implemented",
        )),
        TypedValue::Bytes(_) => Err(GnmiError::from(Encoding::Bytes)),
        TypedValue::Ascii(_) => Err(GnmiError::from(Encoding::Ascii)),
        TypedValue::Proto(_) => Err(GnmiError::from(Encoding::Proto)),
    }
}

fn bytes_to_utf8(bytes: &[u8]) -> Result<&str, GnmiError> {
    std::str::from_utf8(bytes).map_err(|_| GnmiError::invalid("gNMI JSON value is not UTF-8"))
}

fn scalar_to_normalized(
    encoding: Encoding,
    value: Value,
    limits: &MgmtLimits,
) -> Result<NormalizedValue, GnmiError> {
    let json =
        serde_json::to_string(&value).map_err(|_| GnmiError::invalid("invalid scalar value"))?;
    NormalizedValue::new(encoding, json, limits)
}

fn finite_float_to_normalized(
    value: f64,
    limits: &MgmtLimits,
) -> Result<NormalizedValue, GnmiError> {
    if !value.is_finite() {
        return Err(GnmiError::invalid(
            "gNMI floating-point value is not finite",
        ));
    }
    let Some(number) = serde_json::Number::from_f64(value) else {
        return Err(GnmiError::invalid(
            "gNMI floating-point value is not valid JSON",
        ));
    };
    scalar_to_normalized(Encoding::JsonIetf, Value::Number(number), limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_values_are_validated_and_compacted() {
        let limits = MgmtLimits::default();
        let value = normalize_typed_value(
            &TypedValue::JsonIetf(br#"{ "b": true, "a": [1, 2] }"#.to_vec()),
            &limits,
        )
        .expect("json");
        assert_eq!(value.encoding(), Encoding::JsonIetf);
        assert!(value.json().contains("\"a\":[1,2]"));

        assert!(normalize_typed_value(&TypedValue::JsonIetf(b"{bad".to_vec()), &limits).is_err());
        assert!(normalize_typed_value(&TypedValue::JsonIetf(vec![0xff]), &limits).is_err());
    }

    #[test]
    fn scalar_values_become_json_ietf() {
        let limits = MgmtLimits::default();
        assert_eq!(
            normalize_typed_value(&TypedValue::String("amf".into()), &limits)
                .expect("string")
                .json(),
            "\"amf\""
        );
        assert_eq!(
            normalize_typed_value(&TypedValue::Bool(true), &limits)
                .expect("bool")
                .json(),
            "true"
        );
        assert_eq!(
            normalize_typed_value(&TypedValue::Uint(42), &limits)
                .expect("uint")
                .json(),
            "42"
        );
    }

    #[test]
    fn unsupported_encodings_fail_closed() {
        let limits = MgmtLimits::default();
        let unsupported = [
            TypedValue::Bytes(vec![1, 2, 3]),
            TypedValue::Ascii("secret-ascii".to_string()),
            TypedValue::Proto(vec![1, 2, 3]),
        ];
        for value in unsupported {
            assert_eq!(
                normalize_typed_value(&value, &limits)
                    .unwrap_err()
                    .status()
                    .as_str(),
                "UNIMPLEMENTED"
            );
        }
        assert!(normalize_typed_value(&TypedValue::Double(f64::NAN), &limits).is_err());
    }

    #[test]
    fn value_limit_is_enforced() {
        let limits = MgmtLimits {
            max_value_bytes: 4,
            ..MgmtLimits::default()
        };
        limits.validate().expect("valid limits");
        assert!(normalize_typed_value(&TypedValue::String("12345".into()), &limits).is_err());
    }
}
