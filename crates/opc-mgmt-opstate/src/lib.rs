//! NF-supplied operational-state provider contract for the OpenPacketCore
//! management plane.
//!
//! Configuration lives in `opc-config-bus`; config-false (operational/state) data
//! does not. gNMI `Get(STATE|OPERATIONAL|ALL)` and NETCONF `<get>` read that data
//! from the consuming NF through [`OperationalStateProvider`].
//!
//! The contract is **anti-fabrication**: a provider returns a value only for a
//! path it can actually supply. A requested path that is absent from the response
//! means "no operational data here" (the server omits it) — it is *not* an error,
//! and the provider must never invent a value, or an [`Origin`] it does not know.
//!
//! Paths are carried as SDK-canonical [`opc_config_model::YangPath`] values,
//! normally produced by `opc-mgmt-path` after schema validation. Values are
//! carried as syntax-checked RFC 7951 JSON strings so this crate stays decoupled
//! from any generated model. The streaming on-change subscription consumed by
//! gNMI `Subscribe` / NETCONF notifications is added in the Subscribe slice.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use opc_config_model::YangPath;
use thiserror::Error;

/// NMDA origin (RFC 8342 `ietf-origin`) of an operational value.
///
/// `#[non_exhaustive]`: the origin identity set may grow; matchers must include a
/// wildcard.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Value comes from intended configuration.
    Intended,
    /// Value comes from a dynamic configuration datastore.
    Dynamic,
    /// Value was set by the system/NF itself.
    System,
    /// Value was learned dynamically (e.g. from a protocol).
    Learned,
    /// Value is a schema default.
    Default,
    /// Origin is genuinely unknown to the provider.
    Unknown,
}

impl Origin {
    /// YANG module name for the RFC 8342 origin identities.
    pub const MODULE: &'static str = "ietf-origin";

    /// Conventional YANG prefix for [`Self::MODULE`].
    pub const PREFIX: &'static str = "or";

    /// Stable unprefixed `ietf-origin` identity local name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intended => "intended",
            Self::Dynamic => "dynamic",
            Self::System => "system",
            Self::Learned => "learned",
            Self::Default => "default",
            Self::Unknown => "unknown",
        }
    }

    /// Stable identity reference using the conventional `ietf-origin` prefix.
    pub const fn prefixed(self) -> &'static str {
        match self {
            Self::Intended => "or:intended",
            Self::Dynamic => "or:dynamic",
            Self::System => "or:system",
            Self::Learned => "or:learned",
            Self::Default => "or:default",
            Self::Unknown => "or:unknown",
        }
    }
}

/// A request for operational state at one or more schema paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationalRequest {
    /// SDK-canonical paths the server is reading; list instances include their
    /// canonical key predicates when the northbound request addressed one.
    pub paths: Vec<YangPath>,
    /// Whether the caller wants NMDA origin metadata (NMDA `get-data` with
    /// `with-origin`); providers attach [`Origin`] only when this is set.
    pub include_origin: bool,
}

impl OperationalRequest {
    /// A request for the given paths without origin metadata.
    pub fn new(paths: impl IntoIterator<Item = YangPath>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
            include_origin: false,
        }
    }

    /// Returns the requested paths.
    pub fn paths(&self) -> &[YangPath] {
        &self.paths
    }

    /// Requests NMDA origin metadata for the reported values.
    pub fn with_origin(mut self) -> Self {
        self.include_origin = true;
        self
    }
}

/// One reported operational value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalValue {
    /// The SDK-canonical path the value is reported at.
    path: YangPath,
    /// RFC 7951 JSON encoding of the value or subtree.
    value_json: String,
    /// NMDA origin, present only when requested and genuinely known.
    origin: Option<Origin>,
}

impl OperationalValue {
    /// Builds a reported value and validates that the supplied payload is JSON.
    ///
    /// This proves JSON syntax only. Schema-specific RFC 7951 correctness still
    /// belongs to the generated model/provider that knows the node type.
    pub fn new(
        path: YangPath,
        value_json: impl Into<String>,
    ) -> Result<Self, OperationalValueError> {
        let value_json = value_json.into();
        serde_json::from_str::<serde_json::Value>(&value_json)
            .map_err(|_| OperationalValueError::InvalidJson)?;
        Ok(Self {
            path,
            value_json,
            origin: None,
        })
    }

    /// Attaches origin metadata. Callers should pass `None` unless origin was
    /// requested and is genuinely known.
    pub fn with_origin(mut self, origin: Option<Origin>) -> Self {
        self.origin = origin;
        self
    }

    /// The SDK-canonical path the value is reported at.
    pub fn path(&self) -> &YangPath {
        &self.path
    }

    /// RFC 7951 JSON encoding of the value or subtree.
    pub fn value_json(&self) -> &str {
        &self.value_json
    }

    /// NMDA origin, present only when requested and genuinely known.
    pub fn origin(&self) -> Option<Origin> {
        self.origin
    }
}

/// A malformed operational value supplied by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OperationalValueError {
    /// The payload was not syntactically valid JSON.
    #[error("operational value is not valid RFC 7951 JSON")]
    InvalidJson,
}

/// The values a provider could supply for a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationalResponse {
    /// Reported values. Contains only paths the provider can supply; requested
    /// paths with no data are simply absent (anti-fabrication).
    pub values: Vec<OperationalValue>,
}

impl OperationalResponse {
    /// Builds a response from a value list.
    pub fn new(values: impl IntoIterator<Item = OperationalValue>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    /// Returns the reported value for a path, if the provider supplied one.
    pub fn value_for(&self, path: &YangPath) -> Option<&OperationalValue> {
        self.values.iter().find(|value| value.path() == path)
    }

    /// Validates a provider response against the request that produced it.
    ///
    /// A valid response reports each path at most once, reports only requested
    /// paths, and includes origin metadata only when the request asked for it.
    pub fn validate_for_request(
        &self,
        request: &OperationalRequest,
    ) -> Result<(), OperationalResponseError> {
        let requested = request.paths.iter().collect::<HashSet<_>>();
        let mut seen = HashSet::new();

        for value in &self.values {
            if !requested.contains(value.path()) {
                return Err(OperationalResponseError::UnexpectedPath);
            }
            if !seen.insert(value.path()) {
                return Err(OperationalResponseError::DuplicatePath);
            }
            if !request.include_origin && value.origin().is_some() {
                return Err(OperationalResponseError::UnexpectedOrigin);
            }
        }

        Ok(())
    }
}

/// A malformed operational-state response supplied by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OperationalResponseError {
    /// A value was reported for a path that was not requested.
    #[error("operational response included an unrequested path")]
    UnexpectedPath,
    /// More than one value was reported for the same path.
    #[error("operational response included a duplicate path")]
    DuplicatePath,
    /// Origin metadata was reported for a request that did not ask for origin.
    #[error("operational response included unexpected origin metadata")]
    UnexpectedOrigin,
}

/// A failure reading operational state. A path the provider simply does not have
/// is **not** an error (it is omitted from the response); these variants are for
/// genuine failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationalError {
    /// The operational data source is temporarily unavailable (retryable).
    #[error("operational state unavailable")]
    Unavailable {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
    /// An internal provider error.
    #[error("operational provider error")]
    Internal {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
    /// The provider returned a syntactically invalid RFC 7951 JSON value.
    #[error("invalid operational value")]
    InvalidValue,
}

impl OperationalError {
    /// Constructs a retryable backend-unavailable error.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::Unavailable {
            detail: detail.into(),
        }
    }

    /// Constructs a non-retryable provider error.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }

    /// Server-side diagnostic detail, if one exists.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Unavailable { detail } | Self::Internal { detail } => Some(detail),
            Self::InvalidValue => None,
        }
    }
}

impl From<OperationalValueError> for OperationalError {
    fn from(_value: OperationalValueError) -> Self {
        Self::InvalidValue
    }
}

impl From<OperationalResponseError> for OperationalError {
    fn from(_value: OperationalResponseError) -> Self {
        Self::InvalidValue
    }
}

/// The NF-supplied operational-state source the management plane reads for
/// config-false data. Implemented by the consuming CNF.
pub trait OperationalStateProvider: Send + Sync {
    /// Returns operational values for the requested paths.
    ///
    /// Implementations MUST omit any requested path they cannot supply rather
    /// than fabricating a value, and MUST attach [`Origin`] only when
    /// `request.include_origin` is set and the origin is genuinely known.
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> YangPath {
        YangPath::new(value).expect("valid test path")
    }

    /// A provider that knows uptime (with a system origin) but nothing else.
    struct UptimeOnly;

    impl OperationalStateProvider for UptimeOnly {
        fn get(
            &self,
            request: &OperationalRequest,
        ) -> Result<OperationalResponse, OperationalError> {
            let mut values = Vec::new();
            for path in &request.paths {
                if path.as_str() == "/sys:system/sys:uptime" {
                    values.push(
                        OperationalValue::new(path.clone(), "42")?
                            .with_origin(request.include_origin.then_some(Origin::System)),
                    );
                }
                // Any other path is genuinely unknown -> omitted (no fabrication).
            }
            Ok(OperationalResponse::new(values))
        }
    }

    #[test]
    fn supplies_known_path_and_omits_unknown() {
        let provider = UptimeOnly;
        let uptime = path("/sys:system/sys:uptime");
        let unknown = path("/sys:system/sys:unknown");
        let response = provider
            .get(&OperationalRequest::new([uptime.clone(), unknown.clone()]))
            .expect("get");

        // Known path supplied.
        let reported = response.value_for(&uptime).expect("uptime present");
        assert_eq!(reported.value_json(), "42");
        // Unknown path omitted, not fabricated.
        assert!(response.value_for(&unknown).is_none());
        assert_eq!(response.values.len(), 1);
    }

    #[test]
    fn origin_only_when_requested() {
        let provider = UptimeOnly;

        let without = provider
            .get(&OperationalRequest::new([path("/sys:system/sys:uptime")]))
            .expect("get");
        assert_eq!(without.values[0].origin(), None);

        let with = provider
            .get(&OperationalRequest::new([path("/sys:system/sys:uptime")]).with_origin())
            .expect("get");
        assert_eq!(with.values[0].origin(), Some(Origin::System));
    }

    #[test]
    fn origin_strings_are_stable() {
        assert_eq!(Origin::MODULE, "ietf-origin");
        assert_eq!(Origin::PREFIX, "or");
        assert_eq!(Origin::Intended.as_str(), "intended");
        assert_eq!(Origin::Dynamic.as_str(), "dynamic");
        assert_eq!(Origin::System.as_str(), "system");
        assert_eq!(Origin::Learned.as_str(), "learned");
        assert_eq!(Origin::Default.as_str(), "default");
        assert_eq!(Origin::Unknown.as_str(), "unknown");
        assert_eq!(Origin::Intended.prefixed(), "or:intended");
        assert_eq!(Origin::Dynamic.prefixed(), "or:dynamic");
        assert_eq!(Origin::System.prefixed(), "or:system");
        assert_eq!(Origin::Learned.prefixed(), "or:learned");
        assert_eq!(Origin::Default.prefixed(), "or:default");
        assert_eq!(Origin::Unknown.prefixed(), "or:unknown");
    }

    #[test]
    fn operational_values_validate_json_syntax() {
        let valid = OperationalValue::new(path("/sys:system/sys:uptime"), "42")
            .expect("numeric JSON value");
        assert_eq!(valid.value_json(), "42");

        let err = OperationalValue::new(path("/sys:system/sys:uptime"), "{not-json")
            .expect_err("invalid JSON rejected");
        assert_eq!(err, OperationalValueError::InvalidJson);
    }

    #[test]
    fn response_validation_rejects_malformed_provider_output() {
        let uptime = path("/sys:system/sys:uptime");
        let unknown = path("/sys:system/sys:unknown");
        let request = OperationalRequest::new([uptime.clone()]);

        let duplicate = OperationalResponse::new([
            OperationalValue::new(uptime.clone(), "42").expect("json"),
            OperationalValue::new(uptime.clone(), "43").expect("json"),
        ]);
        assert_eq!(
            duplicate.validate_for_request(&request).unwrap_err(),
            OperationalResponseError::DuplicatePath
        );

        let unexpected =
            OperationalResponse::new([OperationalValue::new(unknown, "1").expect("json")]);
        assert_eq!(
            unexpected.validate_for_request(&request).unwrap_err(),
            OperationalResponseError::UnexpectedPath
        );

        let unexpected_origin =
            OperationalResponse::new([OperationalValue::new(uptime.clone(), "42")
                .expect("json")
                .with_origin(Some(Origin::System))]);
        assert_eq!(
            unexpected_origin
                .validate_for_request(&request)
                .unwrap_err(),
            OperationalResponseError::UnexpectedOrigin
        );

        let with_origin_request = OperationalRequest::new([uptime]).with_origin();
        unexpected_origin
            .validate_for_request(&with_origin_request)
            .expect("origin allowed when requested");
    }

    #[test]
    fn errors_are_distinct_from_missing_data() {
        // A provider may signal a genuine failure; this is different from a path
        // simply being absent from a successful response.
        struct Broken;
        impl OperationalStateProvider for Broken {
            fn get(
                &self,
                _request: &OperationalRequest,
            ) -> Result<OperationalResponse, OperationalError> {
                Err(OperationalError::unavailable("provider offline"))
            }
        }
        assert!(matches!(
            Broken.get(&OperationalRequest::new([path("/x")])),
            Err(OperationalError::Unavailable { .. })
        ));
    }

    #[test]
    fn provider_error_display_does_not_expose_detail() {
        let err = OperationalError::internal(
            "failed reading /sys:system/sys:user[sys:name='secret-admin']",
        );
        assert_eq!(err.to_string(), "operational provider error");
        assert_eq!(
            err.detail(),
            Some("failed reading /sys:system/sys:user[sys:name='secret-admin']")
        );
        assert!(!err.to_string().contains("secret-admin"));
    }
}
