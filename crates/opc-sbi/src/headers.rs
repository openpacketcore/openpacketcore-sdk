use http::{
    header::{HeaderName, HeaderValue, ToStrError},
    HeaderMap, Uri,
};
use opc_types::{IntoRedacted, Redacted};
use std::{fmt, str::FromStr, time::Duration};
use thiserror::Error;
use time::{Date, Month, Time, Weekday};

use crate::redact::SensitivePresence;

pub const HEADER_MESSAGE_PRIORITY: &str = "3gpp-sbi-message-priority";
pub const HEADER_CORRELATION_INFO: &str = "3gpp-sbi-correlation-info";
pub const HEADER_BINDING: &str = "3gpp-sbi-binding";
pub const HEADER_ROUTING_BINDING: &str = "3gpp-sbi-routing-binding";
pub const HEADER_TARGET_API_ROOT: &str = "3gpp-sbi-target-apiroot";
pub const HEADER_RETRY_AFTER: &str = "retry-after";
pub const HEADER_LOCATION: &str = "location";
pub const HEADER_AUTHORIZATION: &str = "authorization";
pub const HEADER_IDEMPOTENCY_KEY: &str = "idempotency-key";
pub const HEADER_DEADLINE_HINT_MS: &str = "x-opc-deadline-ms";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderParseError {
    #[error("header '{header}' is not valid UTF-8")]
    NonUtf8 { header: &'static str },
    #[error("header '{header}' must not be empty")]
    Empty { header: &'static str },
    #[error("header '{header}' must not be repeated")]
    Duplicate { header: &'static str },
    #[error("header '{header}' is invalid: {reason}")]
    InvalidValue {
        header: &'static str,
        reason: String,
    },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BearerToken(Redacted<String>);

impl BearerToken {
    pub fn new(value: impl Into<String>) -> Result<Self, HeaderParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HeaderParseError::Empty {
                header: HEADER_AUTHORIZATION,
            });
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(HeaderParseError::InvalidValue {
                header: HEADER_AUTHORIZATION,
                reason: "bearer token must not contain whitespace or control characters".into(),
            });
        }
        validate_b64token(&value)?;
        Ok(Self(value.redacted()))
    }

    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    pub fn into_inner(self) -> String {
        self.0.into_inner()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationHeader {
    Bearer(BearerToken),
    Opaque {
        scheme: String,
        credentials: Redacted<String>,
    },
}

impl AuthorizationHeader {
    pub fn parse(value: &str) -> Result<Self, HeaderParseError> {
        let mut parts = value.split_ascii_whitespace();
        let scheme = parts.next().ok_or(HeaderParseError::Empty {
            header: HEADER_AUTHORIZATION,
        })?;
        let credentials = parts.next().ok_or_else(|| HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "authorization header must contain credentials".into(),
        })?;

        if parts.next().is_some() {
            return Err(HeaderParseError::InvalidValue {
                header: HEADER_AUTHORIZATION,
                reason: "authorization header must contain exactly scheme and credentials".into(),
            });
        }

        if scheme.eq_ignore_ascii_case("Bearer") {
            Ok(Self::Bearer(BearerToken::new(credentials.to_owned())?))
        } else {
            if credentials.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(HeaderParseError::InvalidValue {
                    header: HEADER_AUTHORIZATION,
                    reason: "credentials must not contain control characters".into(),
                });
            }
            Ok(Self::Opaque {
                scheme: scheme.to_owned(),
                credentials: credentials.to_owned().redacted(),
            })
        }
    }

    pub fn bearer_token(&self) -> Option<&BearerToken> {
        match self {
            Self::Bearer(token) => Some(token),
            Self::Opaque { .. } => None,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {}", token.expose()),
            Self::Opaque {
                scheme,
                credentials,
            } => format!("{scheme} {}", credentials.expose()),
        }
    }
}

impl fmt::Debug for AuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
            Self::Opaque { scheme, .. } => f
                .debug_struct("Opaque")
                .field("scheme", scheme)
                .field("credentials", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAfter {
    DelaySeconds(u32),
    HttpDate(String),
}

impl RetryAfter {
    pub fn parse(value: &str) -> Result<Self, HeaderParseError> {
        let raw = trim_non_empty(HEADER_RETRY_AFTER, value)?;
        if raw.bytes().all(|byte| byte.is_ascii_digit()) {
            let seconds = raw
                .parse::<u32>()
                .map_err(|_| HeaderParseError::InvalidValue {
                    header: HEADER_RETRY_AFTER,
                    reason: "retry-after delay must fit within u32 seconds".into(),
                })?;
            Ok(Self::DelaySeconds(seconds))
        } else {
            parse_http_date(raw)?;
            Ok(Self::HttpDate(raw.to_owned()))
        }
    }

    pub fn as_duration(&self) -> Option<Duration> {
        match self {
            Self::DelaySeconds(value) => Some(Duration::from_secs(u64::from(*value))),
            Self::HttpDate(_) => None,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Self::DelaySeconds(seconds) => seconds.to_string(),
            Self::HttpDate(date) => date.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct SbiHeaders {
    /// Message priority (0–7), mapped from the 3GPP QosIdentifier field.
    /// TS 29.500 defines QosIdentifier as 0–255, but this implementation
    /// restricts the field to 0–7 per the SBI message priority semantics.
    pub message_priority: Option<u8>,
    pub correlation_info: Option<String>,
    pub binding: Option<String>,
    pub routing_binding: Option<String>,
    pub target_api_root: Option<Uri>,
    pub retry_after: Option<RetryAfter>,
    pub location: Option<Uri>,
    pub authorization: Option<AuthorizationHeader>,
}

impl SbiHeaders {
    pub fn parse(headers: &HeaderMap) -> Result<Self, HeaderParseError> {
        Ok(Self {
            message_priority: optional_header_value(headers, HEADER_MESSAGE_PRIORITY)?
                .map(parse_message_priority)
                .transpose()?,
            correlation_info: optional_header_value(headers, HEADER_CORRELATION_INFO)?
                .map(|value| parse_non_sensitive_string(HEADER_CORRELATION_INFO, value))
                .transpose()?,
            binding: optional_header_value(headers, HEADER_BINDING)?
                .map(|value| parse_non_sensitive_string(HEADER_BINDING, value))
                .transpose()?,
            routing_binding: optional_header_value(headers, HEADER_ROUTING_BINDING)?
                .map(|value| parse_non_sensitive_string(HEADER_ROUTING_BINDING, value))
                .transpose()?,
            target_api_root: optional_header_value(headers, HEADER_TARGET_API_ROOT)?
                .map(|value| parse_uri_header(HEADER_TARGET_API_ROOT, value))
                .transpose()?,
            retry_after: optional_header_value(headers, HEADER_RETRY_AFTER)?
                .map(RetryAfter::parse)
                .transpose()?,
            location: optional_header_value(headers, HEADER_LOCATION)?
                .map(|value| parse_uri_header(HEADER_LOCATION, value))
                .transpose()?,
            authorization: optional_header_value(headers, HEADER_AUTHORIZATION)?
                .map(AuthorizationHeader::parse)
                .transpose()?,
        })
    }

    pub fn render(&self) -> Result<HeaderMap, HeaderParseError> {
        let mut headers = HeaderMap::new();

        if let Some(priority) = self.message_priority {
            insert_header(&mut headers, HEADER_MESSAGE_PRIORITY, &priority.to_string())?;
        }
        if let Some(correlation_info) = &self.correlation_info {
            insert_header(&mut headers, HEADER_CORRELATION_INFO, correlation_info)?;
        }
        if let Some(binding) = &self.binding {
            insert_header(&mut headers, HEADER_BINDING, binding)?;
        }
        if let Some(routing_binding) = &self.routing_binding {
            insert_header(&mut headers, HEADER_ROUTING_BINDING, routing_binding)?;
        }
        if let Some(target_api_root) = &self.target_api_root {
            insert_header(
                &mut headers,
                HEADER_TARGET_API_ROOT,
                &target_api_root.to_string(),
            )?;
        }
        if let Some(retry_after) = &self.retry_after {
            insert_header(&mut headers, HEADER_RETRY_AFTER, &retry_after.render())?;
        }
        if let Some(location) = &self.location {
            insert_header(&mut headers, HEADER_LOCATION, &location.to_string())?;
        }
        if let Some(authorization) = &self.authorization {
            insert_header(&mut headers, HEADER_AUTHORIZATION, &authorization.render())?;
        }

        Ok(headers)
    }
}

impl fmt::Debug for SbiHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiHeaders")
            .field("message_priority", &self.message_priority)
            .field(
                "correlation_info",
                &SensitivePresence(self.correlation_info.is_some()),
            )
            .field("binding", &SensitivePresence(self.binding.is_some()))
            .field(
                "routing_binding",
                &SensitivePresence(self.routing_binding.is_some()),
            )
            .field(
                "target_api_root",
                &SensitivePresence(self.target_api_root.is_some()),
            )
            .field("retry_after", &self.retry_after)
            .field("location", &SensitivePresence(self.location.is_some()))
            .field(
                "authorization",
                &SensitivePresence(self.authorization.is_some()),
            )
            .finish()
    }
}

pub fn extract_bearer_token(value: &str) -> Result<Option<BearerToken>, HeaderParseError> {
    let parsed = AuthorizationHeader::parse(value)?;
    Ok(parsed.bearer_token().cloned())
}

pub fn extract_bearer_token_from_headers(
    headers: &HeaderMap,
) -> Result<Option<BearerToken>, HeaderParseError> {
    match optional_header_value(headers, HEADER_AUTHORIZATION)? {
        Some(value) => extract_bearer_token(value),
        None => Ok(None),
    }
}

fn optional_header_value<'a>(
    headers: &'a HeaderMap,
    header: &'static str,
) -> Result<Option<&'a str>, HeaderParseError> {
    let mut values = headers.get_all(HeaderName::from_static(header)).iter();
    let first = match values.next() {
        Some(value) => value,
        None => return Ok(None),
    };

    if values.next().is_some() {
        return Err(HeaderParseError::Duplicate { header });
    }

    Ok(Some(to_str(header, first)?))
}

fn to_str<'a>(header: &'static str, value: &'a HeaderValue) -> Result<&'a str, HeaderParseError> {
    value
        .to_str()
        .map_err(|_: ToStrError| HeaderParseError::NonUtf8 { header })
}

fn parse_message_priority(value: &str) -> Result<u8, HeaderParseError> {
    let raw = trim_non_empty(HEADER_MESSAGE_PRIORITY, value)?;
    let priority = raw
        .parse::<u8>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_MESSAGE_PRIORITY,
            reason: "priority must be an integer between 0 and 7".into(),
        })?;
    if priority > 7 {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_MESSAGE_PRIORITY,
            reason: "priority must be between 0 and 7".into(),
        });
    }
    Ok(priority)
}

fn parse_non_sensitive_string(
    header: &'static str,
    value: &str,
) -> Result<String, HeaderParseError> {
    let raw = trim_non_empty(header, value)?;
    validate_visible_ascii(header, raw)?;
    Ok(raw.to_owned())
}

fn parse_uri_header(header: &'static str, value: &str) -> Result<Uri, HeaderParseError> {
    let raw = trim_non_empty(header, value)?;
    raw.parse::<Uri>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header,
            reason: "header must contain a valid URI".into(),
        })
}

fn trim_non_empty<'a>(header: &'static str, value: &'a str) -> Result<&'a str, HeaderParseError> {
    if value.trim() != value {
        return Err(HeaderParseError::InvalidValue {
            header,
            reason: "header value must not contain leading or trailing whitespace".into(),
        });
    }
    if value.is_empty() {
        return Err(HeaderParseError::Empty { header });
    }
    Ok(value)
}

fn validate_visible_ascii(header: &'static str, value: &str) -> Result<(), HeaderParseError> {
    if value
        .bytes()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(HeaderParseError::InvalidValue {
            header,
            reason: "header value must contain only visible ASCII characters".into(),
        });
    }
    Ok(())
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), HeaderParseError> {
    let header_name = HeaderName::from_static(name);
    let value = HeaderValue::from_str(value).map_err(|_| HeaderParseError::InvalidValue {
        header: name,
        reason: "header value cannot be encoded".into(),
    })?;
    headers.insert(header_name, value);
    Ok(())
}

fn validate_b64token(value: &str) -> Result<(), HeaderParseError> {
    let mut saw_padding = false;
    let mut saw_content = false;

    for byte in value.bytes() {
        if is_b64token_char(byte) {
            if saw_padding {
                return Err(HeaderParseError::InvalidValue {
                    header: HEADER_AUTHORIZATION,
                    reason: "bearer token padding must only appear at the end".into(),
                });
            }
            saw_content = true;
            continue;
        }

        if byte == b'=' {
            saw_padding = true;
            continue;
        }

        return Err(HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "bearer token contains characters outside the RFC 6750 b64token grammar".into(),
        });
    }

    if !saw_content {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_AUTHORIZATION,
            reason: "bearer token must contain at least one non-padding character".into(),
        });
    }

    Ok(())
}

fn is_b64token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

fn parse_http_date(value: &str) -> Result<(), HeaderParseError> {
    validate_visible_ascii(HEADER_RETRY_AFTER, value)?;
    if value.len() != 29 {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    let bytes = value.as_bytes();
    if bytes[3] != b','
        || bytes[4] != b' '
        || bytes[7] != b' '
        || bytes[11] != b' '
        || bytes[16] != b' '
        || bytes[19] != b':'
        || bytes[22] != b':'
        || bytes[25] != b' '
        || &value[26..] != "GMT"
    {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    let weekday = parse_weekday(&value[..3])?;
    let day = parse_u8_component(&value[5..7], "day")?;
    let month = parse_month(&value[8..11])?;
    let year = parse_i32_component(&value[12..16], "year")?;
    let hour = parse_u8_component(&value[17..19], "hour")?;
    let minute = parse_u8_component(&value[20..22], "minute")?;
    let second = parse_u8_component(&value[23..25], "second")?;

    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })?;
    Time::from_hms(hour, minute, second).map_err(|_| HeaderParseError::InvalidValue {
        header: HEADER_RETRY_AFTER,
        reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
    })?;

    if date.weekday() != weekday {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        });
    }

    Ok(())
}

fn parse_weekday(value: &str) -> Result<Weekday, HeaderParseError> {
    match value {
        "Mon" => Ok(Weekday::Monday),
        "Tue" => Ok(Weekday::Tuesday),
        "Wed" => Ok(Weekday::Wednesday),
        "Thu" => Ok(Weekday::Thursday),
        "Fri" => Ok(Weekday::Friday),
        "Sat" => Ok(Weekday::Saturday),
        "Sun" => Ok(Weekday::Sunday),
        _ => Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        }),
    }
}

fn parse_month(value: &str) -> Result<Month, HeaderParseError> {
    match value {
        "Jan" => Ok(Month::January),
        "Feb" => Ok(Month::February),
        "Mar" => Ok(Month::March),
        "Apr" => Ok(Month::April),
        "May" => Ok(Month::May),
        "Jun" => Ok(Month::June),
        "Jul" => Ok(Month::July),
        "Aug" => Ok(Month::August),
        "Sep" => Ok(Month::September),
        "Oct" => Ok(Month::October),
        "Nov" => Ok(Month::November),
        "Dec" => Ok(Month::December),
        _ => Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        }),
    }
}

fn parse_u8_component(value: &str, component: &'static str) -> Result<u8, HeaderParseError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: format!("retry-after {component} must be numeric"),
        });
    }

    value
        .parse::<u8>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })
}

fn parse_i32_component(value: &str, component: &'static str) -> Result<i32, HeaderParseError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: format!("retry-after {component} must be numeric"),
        });
    }

    value
        .parse::<i32>()
        .map_err(|_| HeaderParseError::InvalidValue {
            header: HEADER_RETRY_AFTER,
            reason: "retry-after date must be a valid IMF-fixdate HTTP-date".into(),
        })
}

impl FromStr for RetryAfter {
    type Err = HeaderParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_visible_ascii_rejects_control_and_high_bytes() {
        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "hello\x00world").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "control bytes should be rejected"
        );

        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "hello\x7fworld").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "DEL should be rejected"
        );

        let err = validate_visible_ascii(HEADER_CORRELATION_INFO, "café").unwrap_err();
        assert!(
            matches!(err, HeaderParseError::InvalidValue { .. }),
            "non-ASCII bytes should be rejected"
        );
        assert!(err.to_string().contains("visible ASCII"));

        assert!(validate_visible_ascii(HEADER_CORRELATION_INFO, "plain-ascii-123").is_ok());
    }

    #[test]
    fn validate_b64token_rejects_padding_only_and_malformed() {
        // Padding-only tokens must be rejected.
        for token in ["=", "==", "==="] {
            let err = validate_b64token(token).unwrap_err();
            assert!(
                matches!(err, HeaderParseError::InvalidValue { .. }),
                "padding-only token '{token}' should be rejected"
            );
        }

        // Padding after content is allowed.
        assert!(validate_b64token("abc=").is_ok());
        assert!(validate_b64token("ab==").is_ok());

        // Padding in the middle is not allowed.
        let err = validate_b64token("a=b").unwrap_err();
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));

        // Non-b64token characters are rejected.
        let err = validate_b64token("abc,def").unwrap_err();
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));
    }
}
