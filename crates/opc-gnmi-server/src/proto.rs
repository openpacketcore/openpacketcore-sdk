//! Generated OpenConfig gNMI protobuf modules.
//!
//! The `.proto` files are vendored under `proto/` at the tag recorded in
//! `proto/README.md`. Keep this module narrow: public RPC handlers should adapt
//! generated messages into the protocol-neutral foundation types in this crate.

/// gNMI service version declared by the vendored `gnmi.proto`.
pub const GNMI_VERSION: &str = env!("OPC_GNMI_PROTO_VERSION");

/// OpenConfig `gnmi_ext` package.
pub mod gnmi_ext {
    tonic::include_proto!("gnmi_ext");
}

/// OpenConfig `gnmi` package.
pub mod gnmi {
    #![allow(clippy::doc_lazy_continuation)]

    tonic::include_proto!("gnmi");

    /// Encoded file descriptor set for the vendored gNMI proto graph.
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("gnmi_descriptor");
}

// Protobuf serialization retains the authorized protocol values. Diagnostics
// must not copy path predicates or payloads into logs, including when a parent
// request/notification uses its derived formatter.
macro_rules! redacted_debug {
    ($($type:ty => $name:literal),+ $(,)?) => {
        $(
            #[allow(deprecated)]
            impl std::fmt::Debug for $type {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct($name).finish_non_exhaustive()
                }
            }
        )+
    };
}

redacted_debug!(
    gnmi::Path => "Path",
    gnmi::PathElem => "PathElem",
    gnmi::TypedValue => "TypedValue",
    gnmi::typed_value::Value => "TypedValue",
    gnmi::Value => "Value",
);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::gnmi;
    use prost::Message;

    #[test]
    fn any_typed_value_preserves_protobuf_wire_bytes() {
        let value = gnmi::TypedValue {
            value: Some(gnmi::typed_value::Value::AnyVal(prost_types::Any {
                type_url: "t".into(),
                value: vec![1, 2],
            })),
        };
        // gNMI field 9 wraps Any fields 1 (type URL) and 2 (opaque bytes).
        let wire = [0x4a, 7, 0x0a, 1, b't', 0x12, 2, 1, 2];
        assert_eq!(value.encode_to_vec(), wire);
        assert_eq!(gnmi::TypedValue::decode(wire.as_slice()).unwrap(), value);

        let descriptor = prost_types::FileDescriptorSet::decode(gnmi::FILE_DESCRIPTOR_SET)
            .expect("generated descriptors use the same Prost version");
        assert!(descriptor.file.iter().any(|file| {
            file.package.as_deref() == Some("gnmi")
                && file.message_type.iter().any(|message| {
                    message.name.as_deref() == Some("TypedValue")
                        && message.field.iter().any(|field| {
                            field.number == Some(9)
                                && field.type_name.as_deref() == Some(".google.protobuf.Any")
                        })
                })
        }));
    }
}
