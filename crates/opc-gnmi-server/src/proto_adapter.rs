//! Adapters from generated protobuf messages into protocol-neutral gNMI types.

use crate::{
    proto::{gnmi, gnmi_ext},
    Encoding, Extension, GnmiError, GnmiPath, GnmiPathElem, TypedValue,
};

/// Converts a foundation encoding into the generated OpenConfig enum value.
pub const fn encoding_to_proto(encoding: Encoding) -> i32 {
    match encoding {
        Encoding::Json => gnmi::Encoding::Json as i32,
        Encoding::Bytes => gnmi::Encoding::Bytes as i32,
        Encoding::Proto => gnmi::Encoding::Proto as i32,
        Encoding::Ascii => gnmi::Encoding::Ascii as i32,
        Encoding::JsonIetf => gnmi::Encoding::JsonIetf as i32,
    }
}

/// Converts a generated gNMI path into the crate's path adapter type.
#[allow(deprecated)]
pub fn path_from_proto(path: &gnmi::Path) -> Result<GnmiPath, GnmiError> {
    if !path.element.is_empty() {
        return Err(GnmiError::unimplemented(
            "deprecated gNMI string path elements are not supported",
        ));
    }
    Ok(GnmiPath {
        origin: non_empty(path.origin.as_str()),
        target: non_empty(path.target.as_str()),
        elems: path
            .elem
            .iter()
            .map(|elem| {
                let mut keys: Vec<_> = elem
                    .key
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                keys.sort_by(|a, b| a.0.cmp(&b.0));
                GnmiPathElem {
                    name: elem.name.clone(),
                    keys,
                }
            })
            .collect(),
    })
}

/// Converts a generated gNMI `TypedValue` into the crate's bounded value model.
pub fn typed_value_from_proto(value: &gnmi::TypedValue) -> Result<TypedValue, GnmiError> {
    use gnmi::typed_value::Value;
    let Some(value) = value.value.as_ref() else {
        return Err(GnmiError::invalid("gNMI TypedValue is empty"));
    };
    Ok(match value {
        Value::StringVal(value) => TypedValue::String(value.clone()),
        Value::IntVal(value) => TypedValue::Int(*value),
        Value::UintVal(value) => TypedValue::Uint(*value),
        Value::BoolVal(value) => TypedValue::Bool(*value),
        Value::BytesVal(value) => TypedValue::Bytes(value.clone()),
        Value::FloatVal(value) => TypedValue::Float(*value),
        Value::DoubleVal(value) => TypedValue::Double(*value),
        Value::DecimalVal(_) => {
            return Err(GnmiError::unimplemented(
                "deprecated gNMI decimal64 TypedValue is not supported",
            ))
        }
        Value::LeaflistVal(_) => TypedValue::LeafList,
        Value::AnyVal(value) => TypedValue::Proto(value.value.clone()),
        Value::JsonVal(value) => TypedValue::Json(value.clone()),
        Value::JsonIetfVal(value) => TypedValue::JsonIetf(value.clone()),
        Value::AsciiVal(value) => TypedValue::Ascii(value.clone()),
        Value::ProtoBytes(value) => TypedValue::Proto(value.clone()),
    })
}

/// Converts a generated gNMI extension into the crate's extension policy input.
///
/// OpenConfig `gnmi_ext.Extension` does not carry a generic criticality bit. For
/// this skeleton, registered extensions are treated as critical because the
/// server has no per-extension semantics yet; well-known master-arbitration and
/// history extensions are rejected before request handling.
pub fn extension_from_proto(extension: &gnmi_ext::Extension) -> Result<Extension, GnmiError> {
    use gnmi_ext::extension::Ext;
    match extension.ext.as_ref() {
        Some(Ext::RegisteredExt(ext)) => {
            let id = u32::try_from(ext.id)
                .map_err(|_| GnmiError::invalid("invalid registered gNMI extension id"))?;
            Ok(Extension::new(id, true, ext.msg.clone()))
        }
        Some(Ext::MasterArbitration(_)) => Err(GnmiError::unimplemented(
            "gNMI master-arbitration extension is not implemented",
        )),
        Some(Ext::History(_)) => Err(GnmiError::unimplemented(
            "gNMI history extension is not implemented",
        )),
        None => Err(GnmiError::invalid("gNMI extension is empty")),
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn path_adapter_rejects_deprecated_string_elements() {
        let path = gnmi::Path {
            element: vec!["system".to_string()],
            origin: String::new(),
            elem: Vec::new(),
            target: String::new(),
        };
        let err = path_from_proto(&path).unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
    }

    #[test]
    fn path_adapter_sorts_key_map_for_deterministic_foundation_input() {
        let path = gnmi::Path {
            element: Vec::new(),
            origin: "demo-system".to_string(),
            elem: vec![gnmi::PathElem {
                name: "flow".to_string(),
                key: [
                    ("z".to_string(), "last".to_string()),
                    ("a".to_string(), "first".to_string()),
                ]
                .into_iter()
                .collect(),
            }],
            target: String::new(),
        };
        let converted = path_from_proto(&path).expect("path");
        assert_eq!(converted.origin.as_deref(), Some("demo-system"));
        assert_eq!(
            converted.elems[0].keys,
            vec![
                ("a".to_string(), "first".to_string()),
                ("z".to_string(), "last".to_string())
            ]
        );
    }

    #[test]
    fn typed_value_adapter_preserves_supported_shapes_and_rejects_empty() {
        let json = gnmi::TypedValue {
            value: Some(gnmi::typed_value::Value::JsonIetfVal(
                br#"{"x":1}"#.to_vec(),
            )),
        };
        assert_eq!(
            typed_value_from_proto(&json).expect("json"),
            TypedValue::JsonIetf(br#"{"x":1}"#.to_vec())
        );

        let empty = gnmi::TypedValue { value: None };
        assert_eq!(
            typed_value_from_proto(&empty)
                .unwrap_err()
                .status()
                .as_str(),
            "INVALID_ARGUMENT"
        );
    }

    #[test]
    fn registered_extension_adapter_treats_unknown_as_critical_without_payload_leak() {
        let proto = gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                gnmi_ext::RegisteredExtension {
                    id: gnmi_ext::ExtensionId::EidExperimental as i32,
                    msg: b"secret-extension-payload".to_vec(),
                },
            )),
        };
        let ext = extension_from_proto(&proto).expect("registered");
        assert_eq!(ext.id, gnmi_ext::ExtensionId::EidExperimental as u32);
        assert!(ext.critical);
        assert_eq!(ext.payload, b"secret-extension-payload");

        let unsupported = gnmi_ext::Extension {
            ext: Some(gnmi_ext::extension::Ext::History(gnmi_ext::History {
                request: None,
            })),
        };
        let err = extension_from_proto(&unsupported).unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert!(!err.to_string().contains("secret"));
    }
}
