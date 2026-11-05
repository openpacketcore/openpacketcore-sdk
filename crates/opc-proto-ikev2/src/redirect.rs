//! Typed RFC 5685 redirect Notify codecs.
//!
//! The caller supplies the verified exchange direction. These codecs do not
//! authenticate a sender, correlate an echoed nonce, authorize a target, or
//! establish an IKE SA. RFC 5685 section 6 first/final IKE_AUTH placement,
//! AUTH verification, redirect-loop limits and trust remain caller duties.
//! A gateway MUST NOT send REDIRECT unless the peer indicated support in its
//! initial request (RFC 5685 §3). Retain that fact across exchanges; the support
//! collector exposes it without retaining session state. A redirected client
//! sends REDIRECTED_FROM in its next initial request.
//!
//! @spec IETF RFC5685 3, 5, 6, 9, 12; IETF RFC7296 3.5, 3.9, 3.10; IETF RFC1035 2.3.3, 2.3.4, 3.1
//! @conformance boundary-only

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{
    notify::{Ikev2NotifyPayload, IKEV2_NOTIFY_PROTOCOL_ID_NONE},
    sa_init::{encode_notify_payload_build, Ikev2NotifyPayloadBuild},
    Ikev2ValidationProfile,
};

pub use crate::notify::{
    IKEV2_NOTIFY_REDIRECT, IKEV2_NOTIFY_REDIRECTED_FROM, IKEV2_NOTIFY_REDIRECT_SUPPORTED,
};

/// Maximum input count for the optional support collector, including unrelated
/// Notifies. This is an SDK work bound, not an RFC cardinality requirement.
pub const IKEV2_REDIRECT_MAX_NOTIFIES: usize = 64;

/// Caller-confirmed exchange direction for interpreting a redirect Notify.
///
/// This value is context, not proof of authentication. In particular,
/// `IkeAuthResponse` does not establish first/final response placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2RedirectContext {
    /// Initial request from the original initiator.
    SaInitRequest,
    /// Initial response from the original responder; REDIRECT echoes Ni.
    SaInitResponse,
    /// First or final IKE_AUTH response from the original responder.
    IkeAuthResponse,
    /// Protected INFORMATIONAL request from the original responder.
    InformationalRequest,
}

/// Gateway identity without routing, resolution or authorization authority.
///
/// The enum can represent an unchecked FQDN draft; encoders validate it.
/// Decoders borrow ASCII text without changing case or a final root dot.
/// Equality compares bytes, not DNS names, target authorization or redirect
/// loops. Callers own DNS case/root-dot normalization (RFC 1035 §2.3.3).
///
/// Registry extensions require callers to handle unknown variants:
/// ```compile_fail
/// use opc_proto_ikev2::Ikev2RedirectGatewayIdentity;
/// fn kind(value: Ikev2RedirectGatewayIdentity<'_>) -> u8 {
///     match value {
///         Ikev2RedirectGatewayIdentity::Ipv4(_) => 1,
///         Ikev2RedirectGatewayIdentity::Ipv6(_) => 2,
///         Ikev2RedirectGatewayIdentity::Fqdn(_) => 3,
///     }
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2RedirectGatewayIdentity<'a> {
    /// Four address octets, gateway identity type 1.
    Ipv4(Ipv4Addr),
    /// Sixteen address octets, gateway identity type 2.
    Ipv6(Ipv6Addr),
    /// Dotted ASCII FQDN text, gateway identity type 3. Backslash escapes,
    /// whitespace and controls are rejected as SDK text policy.
    Fqdn(&'a str),
}

impl fmt::Debug for Ikev2RedirectGatewayIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ipv4(_) => "Ipv4(<redacted>)",
            Self::Ipv6(_) => "Ipv6(<redacted>)",
            Self::Fqdn(_) => "Fqdn(<redacted>)",
        })
    }
}

/// A typed redirect Notify draft or a structurally decoded value.
///
/// Builders validate every draft. Receiving a value grants no redirect or
/// authentication authority. Echoed nonces must match the caller's original Ni.
///
/// External matches must allow future notification representations:
/// ```compile_fail
/// use opc_proto_ikev2::Ikev2RedirectNotify;
/// fn exhaustive(value: Ikev2RedirectNotify<'_>) {
///     match value {
///         Ikev2RedirectNotify::Supported => {},
///         Ikev2RedirectNotify::Redirect { .. } => {},
///         Ikev2RedirectNotify::RedirectedFrom(_) => {},
///     }
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2RedirectNotify<'a> {
    /// Empty REDIRECT_SUPPORTED in an initial request.
    Supported,
    /// REDIRECT with an identity and an echoed Ni only for SA_INIT responses.
    Redirect {
        /// Target gateway identity.
        gateway: Ikev2RedirectGatewayIdentity<'a>,
        /// Original peer Ni, required only in an SA_INIT response.
        nonce: Option<&'a [u8]>,
    },
    /// Original gateway IP in a redirected initial request (RFC 5685 §9.3).
    /// A DNS name cannot be represented here:
    /// ```compile_fail
    /// use opc_proto_ikev2::{Ikev2RedirectGatewayIdentity, Ikev2RedirectNotify};
    /// let value = Ikev2RedirectNotify::RedirectedFrom(
    ///     Ikev2RedirectGatewayIdentity::Fqdn("vpn.example"));
    /// ```
    RedirectedFrom(IpAddr),
}

impl fmt::Debug for Ikev2RedirectNotify<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Supported => "Supported",
            Self::Redirect { .. } => "Redirect(<redacted>)",
            Self::RedirectedFrom(_) => "RedirectedFrom(<redacted>)",
        })
    }
}

/// A named, value-free redirect codec or support collection failure.
///
/// External matches must retain a wildcard for future outcomes:
/// ```compile_fail
/// use opc_proto_ikev2::Ikev2RedirectNotifyError as Error;
/// fn exhaustive(value: Error) {
///     match value {
///         Error::WrongContext => {},
///         Error::NonceRequired => {},
///         Error::NonceLengthInvalid => {},
///         Error::NonceProhibited => {},
///         Error::GatewayHeaderTruncated => {},
///         Error::GatewayIdentityTypeUnsupported => {},
///         Error::GatewayIdentityEmpty => {},
///         Error::GatewayIdentityTruncated => {},
///         Error::Ipv4LengthInvalid => {},
///         Error::Ipv6LengthInvalid => {},
///         Error::FqdnNonAscii => {},
///         Error::FqdnInvalidCharacter => {},
///         Error::FqdnEmptyLabel => {},
///         Error::FqdnLabelTooLong => {},
///         Error::GatewayIdentityTooLong => {},
///         Error::FqdnNameTooLong => {},
///         Error::RedirectedFromRequiresIp => {},
///         Error::UnexpectedTrailingData => {},
///         Error::SupportedDataNonempty => {},
///         Error::ProtocolIdNonzero => {},
///         Error::SpiSizeNonzero => {},
///         Error::SpiNonempty => {},
///         Error::DuplicateSupported => {},
///         Error::DuplicateRedirectedFrom => {},
///         Error::TooManyNotifies => {},
///         Error::Encoding => {},
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Ikev2RedirectNotifyError {
    /// Recognized type is not valid in the supplied direction.
    #[error("redirect Notify in wrong exchange direction")]
    WrongContext,
    /// SA_INIT response did not contain the echoed peer Ni.
    #[error("redirect peer nonce required")]
    NonceRequired,
    /// Echoed Ni is outside the RFC 5685 16..=256 octet range.
    #[error("redirect peer nonce length invalid")]
    NonceLengthInvalid,
    /// Protected REDIRECT must not contain a nonce, even an empty draft.
    #[error("redirect nonce prohibited in protected exchange")]
    NonceProhibited,
    /// Gateway type and length fields are incomplete.
    #[error("redirect gateway header truncated")]
    GatewayHeaderTruncated,
    /// Gateway identity type is outside the supported RFC registry.
    #[error("redirect gateway identity type unsupported")]
    GatewayIdentityTypeUnsupported,
    /// Gateway identity has zero octets.
    #[error("redirect gateway identity empty")]
    GatewayIdentityEmpty,
    /// Gateway identity length exceeds remaining input.
    #[error("redirect gateway identity truncated")]
    GatewayIdentityTruncated,
    /// IPv4 identity is not four octets.
    #[error("redirect IPv4 identity length invalid")]
    Ipv4LengthInvalid,
    /// IPv6 identity is not sixteen octets.
    #[error("redirect IPv6 identity length invalid")]
    Ipv6LengthInvalid,
    /// FQDN contains non-ASCII octets.
    #[error("redirect FQDN must be ASCII")]
    FqdnNonAscii,
    /// FQDN contains backslash, whitespace, controls or a terminator.
    #[error("redirect FQDN contains invalid character")]
    FqdnInvalidCharacter,
    /// FQDN contains an empty label other than an optional final root dot.
    #[error("redirect FQDN contains empty label")]
    FqdnEmptyLabel,
    /// A DNS label exceeds 63 octets.
    #[error("redirect FQDN label too long")]
    FqdnLabelTooLong,
    /// Identity does not fit the one-octet gateway identity length.
    #[error("redirect gateway identity too long")]
    GatewayIdentityTooLong,
    /// DNS name would exceed 255 octets in DNS wire form.
    #[error("redirect FQDN name too long")]
    FqdnNameTooLong,
    /// REDIRECTED_FROM permits only IPv4 and IPv6 identities.
    #[error("redirected-from requires IP identity")]
    RedirectedFromRequiresIp,
    /// REDIRECTED_FROM has bytes after its identity.
    #[error("redirected-from contains trailing data")]
    UnexpectedTrailingData,
    /// REDIRECT_SUPPORTED is not empty.
    #[error("redirect-supported data must be empty")]
    SupportedDataNonempty,
    /// Sender-canonical auditing requires zero Protocol ID with empty SPI.
    #[error("redirect Notify protocol ID must be zero for sender")]
    ProtocolIdNonzero,
    /// Recognized Notify declares a nonzero SPI size.
    #[error("redirect Notify SPI size must be zero")]
    SpiSizeNonzero,
    /// Recognized Notify view retains SPI octets.
    #[error("redirect Notify SPI must be empty")]
    SpiNonempty,
    /// Support collector encountered REDIRECT_SUPPORTED twice (SDK policy).
    #[error("duplicate redirect-supported Notify")]
    DuplicateSupported,
    /// Support collector encountered REDIRECTED_FROM twice (SDK policy).
    #[error("duplicate redirected-from Notify")]
    DuplicateRedirectedFrom,
    /// Support collector input exceeds the local SDK work bound.
    #[error("redirect support collection limit exceeded")]
    TooManyNotifies,
    /// Generic Notify body encoding failed.
    #[error("redirect Notify encoding failed")]
    Encoding,
}

impl Ikev2RedirectNotifyError {
    /// Stable diagnostic label containing no gateway, nonce or input data.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongContext => "ike_redirect_wrong_context",
            Self::NonceRequired => "ike_redirect_nonce_required",
            Self::NonceLengthInvalid => "ike_redirect_nonce_length_invalid",
            Self::NonceProhibited => "ike_redirect_nonce_prohibited",
            Self::GatewayHeaderTruncated => "ike_redirect_gateway_header_truncated",
            Self::GatewayIdentityTypeUnsupported => {
                "ike_redirect_gateway_identity_type_unsupported"
            }
            Self::GatewayIdentityEmpty => "ike_redirect_gateway_identity_empty",
            Self::GatewayIdentityTruncated => "ike_redirect_gateway_identity_truncated",
            Self::Ipv4LengthInvalid => "ike_redirect_ipv4_length_invalid",
            Self::Ipv6LengthInvalid => "ike_redirect_ipv6_length_invalid",
            Self::FqdnNonAscii => "ike_redirect_fqdn_non_ascii",
            Self::FqdnInvalidCharacter => "ike_redirect_fqdn_invalid_character",
            Self::FqdnEmptyLabel => "ike_redirect_fqdn_empty_label",
            Self::FqdnLabelTooLong => "ike_redirect_fqdn_label_too_long",
            Self::GatewayIdentityTooLong => "ike_redirect_gateway_identity_too_long",
            Self::FqdnNameTooLong => "ike_redirect_fqdn_name_too_long",
            Self::RedirectedFromRequiresIp => "ike_redirect_redirected_from_requires_ip",
            Self::UnexpectedTrailingData => "ike_redirect_unexpected_trailing_data",
            Self::SupportedDataNonempty => "ike_redirect_supported_data_nonempty",
            Self::ProtocolIdNonzero => "ike_redirect_protocol_id_nonzero",
            Self::SpiSizeNonzero => "ike_redirect_spi_size_nonzero",
            Self::SpiNonempty => "ike_redirect_spi_nonempty",
            Self::DuplicateSupported => "ike_redirect_duplicate_supported",
            Self::DuplicateRedirectedFrom => "ike_redirect_duplicate_redirected_from",
            Self::TooManyNotifies => "ike_redirect_too_many_notifies",
            Self::Encoding => "ike_redirect_encoding",
        }
    }
}

impl Ikev2RedirectNotify<'_> {
    /// Convert a gateway draft to the IP-only original-gateway value.
    ///
    /// # Errors
    /// Returns [`Ikev2RedirectNotifyError::RedirectedFromRequiresIp`] for every
    /// FQDN draft, before validating its text, just as the wire decoder rejects
    /// identity type 3 before inspecting its length or text.
    pub fn redirected_from(
        gateway: Ikev2RedirectGatewayIdentity<'_>,
    ) -> Result<Self, Ikev2RedirectNotifyError> {
        match gateway {
            Ikev2RedirectGatewayIdentity::Ipv4(address) => {
                Ok(Self::RedirectedFrom(IpAddr::V4(address)))
            }
            Ikev2RedirectGatewayIdentity::Ipv6(address) => {
                Ok(Self::RedirectedFrom(IpAddr::V6(address)))
            }
            Ikev2RedirectGatewayIdentity::Fqdn(_) => {
                Err(Ikev2RedirectNotifyError::RedirectedFromRequiresIp)
            }
        }
    }

    /// Validate and build canonical generic Notify fields without a payload header.
    ///
    /// Before sending REDIRECT, the caller MUST have retained the peer's
    /// initial support indication. Redirected clients send REDIRECTED_FROM in
    /// the next initial request. This stateless builder verifies neither duty.
    ///
    /// # Errors
    ///
    /// Returns a named error for invalid identity, context or nonce data.
    pub fn to_notify_build(
        self,
        context: Ikev2RedirectContext,
    ) -> Result<Ikev2NotifyPayloadBuild, Ikev2RedirectNotifyError> {
        let mut notification_data = Vec::new();
        let notify_message_type = match self {
            Self::Supported => {
                require_initial_request(context)?;
                IKEV2_NOTIFY_REDIRECT_SUPPORTED
            }
            Self::Redirect { gateway, nonce } => {
                validate_nonce(nonce, context)?;
                append_gateway(&mut notification_data, gateway)?;
                if let Some(nonce) = nonce {
                    notification_data.extend_from_slice(nonce);
                }
                IKEV2_NOTIFY_REDIRECT
            }
            Self::RedirectedFrom(gateway) => {
                require_initial_request(context)?;
                let gateway = match gateway {
                    IpAddr::V4(address) => Ikev2RedirectGatewayIdentity::Ipv4(address),
                    IpAddr::V6(address) => Ikev2RedirectGatewayIdentity::Ipv6(address),
                };
                append_gateway(&mut notification_data, gateway)?;
                IKEV2_NOTIFY_REDIRECTED_FROM
            }
        };
        Ok(Ikev2NotifyPayloadBuild {
            protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            spi: Vec::new(),
            notify_message_type,
            notification_data,
        })
    }
}

/// Build a generic Notify body, excluding its four-octet generic payload header.
///
/// REDIRECT transmission requires the peer's retained initial support
/// indication (RFC 5685 §3); the codec cannot establish that precondition.
///
/// # Errors
///
/// Returns a named validation error or a generic body encoding failure.
pub fn build_ikev2_redirect_notify(
    value: Ikev2RedirectNotify<'_>,
    context: Ikev2RedirectContext,
) -> Result<Vec<u8>, Ikev2RedirectNotifyError> {
    encode_notify_payload_build(&value.to_notify_build(context)?)
        .map_err(|_| Ikev2RedirectNotifyError::Encoding)
}

/// Interpret a Notify with RFC 7296 network receiver semantics.
///
/// An unrelated type returns `Ok(None)` without inspecting its fields. A
/// malformed recognized type is an error. Protocol ID is ignored when SPI is
/// empty, as required by RFC 7296 section 3.10.
///
/// # Errors
///
/// Returns a named structural, context, identity or nonce error.
pub fn decode_ikev2_redirect_notify(
    notify: Ikev2NotifyPayload<'_>,
    context: Ikev2RedirectContext,
) -> Result<Option<Ikev2RedirectNotify<'_>>, Ikev2RedirectNotifyError> {
    decode_ikev2_redirect_notify_with_profile(
        notify,
        context,
        Ikev2ValidationProfile::NetworkReceive,
    )
}

/// Interpret a Notify with an explicit receiver or sender-audit profile.
///
/// Neither profile relaxes SPI, identity, context or nonce validation.
///
/// # Errors
///
/// Returns the same errors as [`decode_ikev2_redirect_notify`], plus nonzero
/// Protocol ID under [`Ikev2ValidationProfile::SenderCanonical`].
pub fn decode_ikev2_redirect_notify_with_profile(
    notify: Ikev2NotifyPayload<'_>,
    context: Ikev2RedirectContext,
    profile: Ikev2ValidationProfile,
) -> Result<Option<Ikev2RedirectNotify<'_>>, Ikev2RedirectNotifyError> {
    use Ikev2RedirectNotifyError as Error;
    if !matches!(
        notify.notify_message_type,
        IKEV2_NOTIFY_REDIRECT_SUPPORTED | IKEV2_NOTIFY_REDIRECT | IKEV2_NOTIFY_REDIRECTED_FROM
    ) {
        return Ok(None);
    }
    if notify.spi_size != 0 {
        return Err(Error::SpiSizeNonzero);
    }
    if !notify.spi.is_empty() {
        return Err(Error::SpiNonempty);
    }
    if profile.requires_sender_canonical_fields()
        && notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE
    {
        return Err(Error::ProtocolIdNonzero);
    }
    let typed = match notify.notify_message_type {
        IKEV2_NOTIFY_REDIRECT_SUPPORTED => {
            require_initial_request(context)?;
            if !notify.notification_data.is_empty() {
                return Err(Error::SupportedDataNonempty);
            }
            Ikev2RedirectNotify::Supported
        }
        IKEV2_NOTIFY_REDIRECT => {
            if context == Ikev2RedirectContext::SaInitRequest {
                return Err(Error::WrongContext);
            }
            let (gateway, tail) = decode_gateway(notify.notification_data)?;
            let nonce = if tail.is_empty() { None } else { Some(tail) };
            validate_nonce(nonce, context)?;
            Ikev2RedirectNotify::Redirect { gateway, nonce }
        }
        _ => {
            require_initial_request(context)?;
            if notify.notification_data.first() == Some(&3) {
                return Err(Error::RedirectedFromRequiresIp);
            }
            let (gateway, tail) = decode_gateway(notify.notification_data)?;
            let original = Ikev2RedirectNotify::redirected_from(gateway)?;
            if !tail.is_empty() {
                return Err(Error::UnexpectedTrailingData);
            }
            original
        }
    };
    Ok(Some(typed))
}

/// Support facts from one complete initial-request collection.
///
/// These facts authenticate no peer and grant no target or routing authority.
/// Retain support across exchanges before sending any REDIRECT (RFC 5685 §3).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Ikev2RedirectSupport {
    supported_notify_present: bool,
    redirected_from: Option<IpAddr>,
}

impl Ikev2RedirectSupport {
    /// Either explicit SUPPORTED or a valid original-gateway IP implies support.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.supported_notify_present || self.redirected_from.is_some()
    }

    /// Whether the collection contained an explicit REDIRECT_SUPPORTED.
    #[must_use]
    pub const fn supported_notify_present(self) -> bool {
        self.supported_notify_present
    }

    /// Original gateway IP, if REDIRECTED_FROM was supplied. Do not log it.
    #[must_use]
    pub const fn redirected_from(self) -> Option<IpAddr> {
        self.redirected_from
    }
}

impl fmt::Debug for Ikev2RedirectSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2RedirectSupport")
            .field("supported_notify_present", &self.supported_notify_present)
            .field("redirected_from_present", &self.redirected_from.is_some())
            .finish()
    }
}

/// Extract support and original-gateway facts from a complete initial request.
///
/// Either SUPPORTED or a valid REDIRECTED_FROM implies support (RFC 5685 §3).
/// Both may coexist. Repeats of either type, even identical, fail under the SDK
/// strict duplicate policy. Unrelated types count toward the local work bound. Any
/// malformed recognized input fails atomically, without a partial result.
/// This function does not authenticate the collection or authorize a redirect.
///
/// # Errors
///
/// Returns a named error for malformed or misplaced recognized input, repeated
/// SUPPORTED/FROM, or more than [`IKEV2_REDIRECT_MAX_NOTIFIES`] total inputs.
/// For every error, this collection establishes no support and supplies no
/// partial original-gateway identity: callers MUST NOT send REDIRECT based on
/// it. Handle malformed/context errors using caller-owned exchange error
/// policy; duplicate and count errors reject the collection under SDK policy.
pub fn decode_ikev2_redirect_support(
    notifies: &[Ikev2NotifyPayload<'_>],
) -> Result<Ikev2RedirectSupport, Ikev2RedirectNotifyError> {
    use Ikev2RedirectNotifyError as Error;
    if notifies.len() > IKEV2_REDIRECT_MAX_NOTIFIES {
        return Err(Error::TooManyNotifies);
    }
    let mut support = Ikev2RedirectSupport::default();
    for &notify in notifies {
        match decode_ikev2_redirect_notify(notify, Ikev2RedirectContext::SaInitRequest)? {
            Some(Ikev2RedirectNotify::Supported) => {
                if support.supported_notify_present {
                    return Err(Error::DuplicateSupported);
                }
                support.supported_notify_present = true;
            }
            Some(Ikev2RedirectNotify::RedirectedFrom(address)) => {
                if support.redirected_from.is_some() {
                    return Err(Error::DuplicateRedirectedFrom);
                }
                support.redirected_from = Some(address);
            }
            _ => {}
        }
    }
    Ok(support)
}

fn require_initial_request(context: Ikev2RedirectContext) -> Result<(), Ikev2RedirectNotifyError> {
    if context != Ikev2RedirectContext::SaInitRequest {
        return Err(Ikev2RedirectNotifyError::WrongContext);
    }
    Ok(())
}

fn validate_nonce(
    nonce: Option<&[u8]>,
    context: Ikev2RedirectContext,
) -> Result<(), Ikev2RedirectNotifyError> {
    use Ikev2RedirectNotifyError as Error;
    match context {
        Ikev2RedirectContext::SaInitRequest => Err(Error::WrongContext),
        Ikev2RedirectContext::SaInitResponse => {
            let nonce = nonce.ok_or(Error::NonceRequired)?;
            if !(16..=256).contains(&nonce.len()) {
                return Err(Error::NonceLengthInvalid);
            }
            Ok(())
        }
        Ikev2RedirectContext::IkeAuthResponse | Ikev2RedirectContext::InformationalRequest => {
            if nonce.is_some() {
                return Err(Error::NonceProhibited);
            }
            Ok(())
        }
    }
}

fn validate_fqdn(bytes: &[u8]) -> Result<&str, Ikev2RedirectNotifyError> {
    use Ikev2RedirectNotifyError as Error;
    if bytes.is_empty() {
        return Err(Error::GatewayIdentityEmpty);
    }
    if bytes.len() > usize::from(u8::MAX) {
        return Err(Error::GatewayIdentityTooLong);
    }
    if !bytes.is_ascii() {
        return Err(Error::FqdnNonAscii);
    }
    if bytes
        .iter()
        .any(|byte| !byte.is_ascii_graphic() || *byte == b'\\')
    {
        return Err(Error::FqdnInvalidCharacter);
    }
    let name = std::str::from_utf8(bytes).map_err(|_| Error::FqdnNonAscii)?;
    let labels = name.strip_suffix('.').unwrap_or(name);
    for label in labels.split('.') {
        if label.is_empty() {
            return Err(Error::FqdnEmptyLabel);
        }
        if label.len() > 63 {
            return Err(Error::FqdnLabelTooLong);
        }
    }
    // DNS wire form adds a length octet per label and the final root label:
    // two more octets than the presentation form without a final root dot.
    if labels.len() + 2 > 255 {
        return Err(Error::FqdnNameTooLong);
    }
    Ok(name)
}

fn append_gateway(
    data: &mut Vec<u8>,
    gateway: Ikev2RedirectGatewayIdentity<'_>,
) -> Result<(), Ikev2RedirectNotifyError> {
    match gateway {
        Ikev2RedirectGatewayIdentity::Ipv4(address) => {
            data.extend_from_slice(&[1, 4]);
            data.extend_from_slice(&address.octets());
        }
        Ikev2RedirectGatewayIdentity::Ipv6(address) => {
            data.extend_from_slice(&[2, 16]);
            data.extend_from_slice(&address.octets());
        }
        Ikev2RedirectGatewayIdentity::Fqdn(name) => {
            validate_fqdn(name.as_bytes())?;
            let len = u8::try_from(name.len())
                .map_err(|_| Ikev2RedirectNotifyError::GatewayIdentityTooLong)?;
            data.extend_from_slice(&[3, len]);
            data.extend_from_slice(name.as_bytes());
        }
    }
    Ok(())
}

fn decode_gateway(
    data: &[u8],
) -> Result<(Ikev2RedirectGatewayIdentity<'_>, &[u8]), Ikev2RedirectNotifyError> {
    use Ikev2RedirectNotifyError as Error;
    let [kind, len, rest @ ..] = data else {
        return Err(Error::GatewayHeaderTruncated);
    };
    if !(1..=3).contains(kind) {
        return Err(Error::GatewayIdentityTypeUnsupported);
    }
    if *len == 0 {
        return Err(Error::GatewayIdentityEmpty);
    }
    let length = usize::from(*len);
    if rest.len() < length {
        return Err(Error::GatewayIdentityTruncated);
    }
    let (identity, tail) = rest.split_at(length);
    let gateway = match kind {
        1 => {
            let octets: [u8; 4] = identity.try_into().map_err(|_| Error::Ipv4LengthInvalid)?;
            Ikev2RedirectGatewayIdentity::Ipv4(Ipv4Addr::from(octets))
        }
        2 => {
            let octets: [u8; 16] = identity.try_into().map_err(|_| Error::Ipv6LengthInvalid)?;
            Ikev2RedirectGatewayIdentity::Ipv6(Ipv6Addr::from(octets))
        }
        _ => Ikev2RedirectGatewayIdentity::Fqdn(validate_fqdn(identity)?),
    };
    Ok((gateway, tail))
}
