//! Opt-in OpenPacketCore committed-revision gNMI response extension.

#![allow(clippy::derive_partial_eq_without_eq)]

use opc_config_model::CommittedConfigRevision;
use prost::Message;

use crate::proto::gnmi_ext::{self, extension::Ext};

/// Experimental registered-extension ID used by OpenPacketCore extensions.
///
/// OpenConfig currently assigns one generic experimental ID (`999`). The
/// request/response context and documented payload type distinguish this
/// response extension from the commit-confirmed request extension.
pub const OPC_COMMITTED_REVISION_EXTENSION_ID: u32 = 999;

/// Stable payload name for the committed-revision response extension.
pub const OPC_COMMITTED_REVISION_EXTENSION_NAME: &str = "openpacketcore.committed-revision.v1";

/// Committed `{version, SHA-256 content hash}` returned by an opt-in gNMI Set.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CommittedRevisionExtension {
    /// Monotonic running-config version committed by this Set.
    #[prost(uint64, tag = "1")]
    pub version: u64,
    /// Exact 32-byte plaintext SHA-256 digest attested by the datastore.
    #[prost(bytes = "vec", tag = "2")]
    pub content_hash: Vec<u8>,
}

impl From<CommittedConfigRevision> for CommittedRevisionExtension {
    fn from(revision: CommittedConfigRevision) -> Self {
        Self {
            version: revision.version.get(),
            content_hash: revision.content_hash.to_vec(),
        }
    }
}

pub(crate) fn response_extension(revision: CommittedConfigRevision) -> gnmi_ext::Extension {
    let payload = CommittedRevisionExtension::from(revision).encode_to_vec();
    gnmi_ext::Extension {
        ext: Some(Ext::RegisteredExt(gnmi_ext::RegisteredExtension {
            id: OPC_COMMITTED_REVISION_EXTENSION_ID as i32,
            msg: payload,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_types::ConfigVersion;

    #[test]
    fn response_extension_round_trips_exact_revision() {
        let extension = response_extension(CommittedConfigRevision::new(
            ConfigVersion::new(42),
            [0xa5; 32],
        ));
        let Some(Ext::RegisteredExt(registered)) = extension.ext else {
            panic!("registered extension");
        };
        assert_eq!(registered.id, OPC_COMMITTED_REVISION_EXTENSION_ID as i32);
        let decoded = match CommittedRevisionExtension::decode(registered.msg.as_slice()) {
            Ok(decoded) => decoded,
            Err(error) => panic!("committed-revision payload did not decode: {error}"),
        };
        assert_eq!(decoded.version, 42);
        assert_eq!(decoded.content_hash, vec![0xa5; 32]);
    }
}
