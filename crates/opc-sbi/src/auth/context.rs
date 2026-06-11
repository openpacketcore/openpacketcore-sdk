use crate::headers::BearerToken;
use crate::redact::SensitivePresence;
use opc_types::{NfInstanceId, NfType, PlmnId, Snssai, SpiffeId, TenantId};
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct SbiPeer {
    pub spiffe: Option<SpiffeId>,
    pub nf_instance_id: Option<NfInstanceId>,
    pub nf_type: Option<NfType>,
    pub tenant: TenantId,
    pub plmn: Option<PlmnId>,
    pub snssai: Option<Snssai>,
}

impl fmt::Debug for SbiPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiPeer")
            .field("spiffe", &SensitivePresence(self.spiffe.is_some()))
            .field(
                "nf_instance_id",
                &SensitivePresence(self.nf_instance_id.is_some()),
            )
            .field("nf_type", &SensitivePresence(self.nf_type.is_some()))
            .field("tenant", &SensitivePresence(true))
            .field("plmn", &SensitivePresence(self.plmn.is_some()))
            .field("snssai", &SensitivePresence(self.snssai.is_some()))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SbiAuthContext {
    pub peer: SbiPeer,
    pub scopes: Vec<String>,
    pub access_token: Option<BearerToken>,
}

impl fmt::Debug for SbiAuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiAuthContext")
            .field("peer", &self.peer)
            .field("scope_count", &self.scopes.len())
            .field(
                "access_token",
                &SensitivePresence(self.access_token.is_some()),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ErasedAuthContext {
    pub spiffe: Option<SpiffeId>,
    pub nf_instance_id: Option<NfInstanceId>,
    pub nf_type: Option<NfType>,
    pub tenant: TenantId,
    pub plmn: Option<PlmnId>,
    pub snssai: Option<Snssai>,
    pub scopes: Vec<String>,
}

impl From<&SbiAuthContext> for ErasedAuthContext {
    fn from(value: &SbiAuthContext) -> Self {
        Self {
            spiffe: value.peer.spiffe.clone(),
            nf_instance_id: value.peer.nf_instance_id.clone(),
            nf_type: value.peer.nf_type.clone(),
            tenant: value.peer.tenant.clone(),
            plmn: value.peer.plmn.clone(),
            snssai: value.peer.snssai.clone(),
            scopes: value.scopes.clone(),
        }
    }
}

impl fmt::Debug for ErasedAuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedAuthContext")
            .field("spiffe", &SensitivePresence(self.spiffe.is_some()))
            .field(
                "nf_instance_id",
                &SensitivePresence(self.nf_instance_id.is_some()),
            )
            .field("nf_type", &SensitivePresence(self.nf_type.is_some()))
            .field("tenant", &SensitivePresence(true))
            .field("plmn", &SensitivePresence(self.plmn.is_some()))
            .field("snssai", &SensitivePresence(self.snssai.is_some()))
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}
