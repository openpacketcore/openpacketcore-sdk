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
