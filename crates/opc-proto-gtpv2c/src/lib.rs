#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! GTPv2-C protocol crate scaffold for OpenPacketCore.
//!
//! This crate provides the trait-oriented shell for a future S2b-focused
//! GTPv2-C codec. The current surface intentionally stops at a
//! raw-preserving, allocation-bounded common-header and IE container layer:
//! it proves integration with [`opc_protocol`] while avoiding claims that
//! typed S2b procedures are already carrier-conformant.
//!
//! @spec 3GPP TS29274 R18
//! @req REQ-3GPP-TS29274-R18-SCAFFOLD-001
//! @conformance scaffold — see CONFORMANCE.md

pub mod header;
pub mod ie;
pub mod message;
pub mod s2b;

pub use header::{decode_header, encode_header, Header, GTPV2C_VERSION};
pub use ie::{validate_ie_region, OwnedRawIe, RawIe, RawIeIterator, IE_HEADER_LEN};
pub use message::{Message, OwnedMessage};
