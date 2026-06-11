use crate::headers::BearerToken;
use crate::redact::SensitivePresence;
use opc_types::{NfInstanceId, NfType, PlmnId, Snssai, SpiffeId, TenantId};
use std::fmt;

/// Authenticated identity of an SBI peer (RFC 007 §9.1).
///
/// Populated from cryptographically verified sources only — mTLS SPIFFE
/// certificates or validated token claims — never from unsigned request
/// headers. `Debug` prints only field presence, not values, so the type is
/// safe to log.
#[derive(Clone, PartialEq, Eq)]
pub struct SbiPeer {
    /// SPIFFE ID from the peer's verified workload certificate or JWT-SVID
    /// `sub` claim; `None` when the transport gave no workload identity.
    pub spiffe: Option<SpiffeId>,
    /// TS 29.510 NF instance ID of the peer, when derivable from its
    /// identity; used to bind tokens to the calling instance.
    pub nf_instance_id: Option<NfInstanceId>,
    /// NF type of the peer (e.g. `amf`, `smf`), used in per-NF-type
    /// authorization and admission decisions.
    pub nf_type: Option<NfType>,
    /// Tenant the peer belongs to. Always present: requests that cannot be
    /// attributed to a tenant are not given a peer identity at all.
    pub tenant: TenantId,
    /// PLMN of the peer, when known; used for inter-PLMN (SEPP) policy.
    pub plmn: Option<PlmnId>,
    /// Network slice (S-NSSAI) binding of the peer, when known; enables
    /// cross-slice isolation checks.
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

/// Successful authorization result produced by an `SbiAuth` policy and
/// attached to the request for downstream handlers.
///
/// Unlike `ErasedAuthContext`, this still carries the validated access
/// token, so it should only flow where re-use of the credential is
/// intended (e.g. token-forwarding middleware).
#[derive(Clone, PartialEq, Eq)]
pub struct SbiAuthContext {
    /// The authenticated peer identity the decision was made for.
    pub peer: SbiPeer,
    /// OAuth2 scopes granted by the validated token (split from the
    /// space-delimited `scope` claim); empty when the token carried none.
    pub scopes: Vec<String>,
    /// The validated bearer token itself, kept redacted; `Debug` shows only
    /// its presence. `None` for policies that authorize without a token.
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

/// Credential-free copy of an `SbiAuthContext` for general handler use.
///
/// Contains the peer identity attributes and granted scopes but **not** the
/// access token, so it can be stored in request extensions and passed around
/// without risking credential leakage. Build it with
/// `ErasedAuthContext::from(&SbiAuthContext)`.
#[derive(Clone, PartialEq, Eq)]
pub struct ErasedAuthContext {
    /// SPIFFE ID of the authenticated peer, when one was established.
    pub spiffe: Option<SpiffeId>,
    /// TS 29.510 NF instance ID of the peer, when known.
    pub nf_instance_id: Option<NfInstanceId>,
    /// NF type of the peer (e.g. `amf`, `smf`), when known.
    pub nf_type: Option<NfType>,
    /// Tenant the peer was authenticated under; always present.
    pub tenant: TenantId,
    /// PLMN binding of the peer, when known.
    pub plmn: Option<PlmnId>,
    /// Network slice (S-NSSAI) binding of the peer, when known.
    pub snssai: Option<Snssai>,
    /// OAuth2 scopes granted to the request by the validated token.
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
