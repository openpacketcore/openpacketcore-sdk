//! Offline Pod-bound bootstrap tokens; trust roots come only from fixed API reads.
use super::proof::BootObservation;
use opc_tls::AuthenticationTimeInterval;
use std::sync::Arc;
/// Bootstrap prerequisite, availability or authentication refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapCredentialError {
    /// The trusted API definitively refuses the issuer-discovery prerequisite.
    #[error("unsupported bootstrap prerequisite")]
    UnsupportedPrerequisite,
    /// Trusted platform source is temporarily unavailable.
    #[error("bootstrap source unavailable")]
    Unavailable,
    /// Token signature or claims do not match the trusted observation.
    #[error("bootstrap credential rejected")]
    Rejected,
    /// The complete authentication interval is outside verified token validity.
    #[error("bootstrap authentication time unavailable")]
    AuthTimeUnavailable,
}
/// Trusted installation adapter. Fetch only the fixed discovery/JWKS paths using
/// the configured API CA and the verifier's own API credential. Bound each body
/// to 64 KiB before allocation. Never follow JWT or discovery-provided URLs.
#[async_trait::async_trait]
pub trait IssuerKeySource: Send + Sync {
    /// GET the configured API's `/.well-known/openid-configuration`. Report a
    /// definitive missing/forbidden discovery binding as UnsupportedPrerequisite;
    /// connection failures and transient API errors are Unavailable.
    async fn discovery(&self) -> Result<Vec<u8>, BootstrapCredentialError>;
    /// GET the configured API's `/openid/v1/jwks`.
    async fn jwks(&self) -> Result<Vec<u8>, BootstrapCredentialError>;
}
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opc_types::Timestamp;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    sync::Mutex,
    time::{timeout, Instant},
};

const SOURCE_DEADLINE: Duration = Duration::from_secs(5);
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const AUDIENCE: &str = "openpacketcore-scope-bootstrap";

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum Algorithm {
    ES256,
    RS256,
}
#[derive(Clone)]
enum Key {
    Ec(VerifyingKey),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}
impl Key {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ec(_) => Algorithm::ES256,
            Self::Rsa { .. } => Algorithm::RS256,
        }
    }
    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<(), BootstrapCredentialError> {
        match self {
            Self::Ec(key) => {
                let signature = Signature::from_slice(signature)
                    .map_err(|_| BootstrapCredentialError::Rejected)?;
                key.verify(input, &signature)
                    .map_err(|_| BootstrapCredentialError::Rejected)
            }
            Self::Rsa { n, e } => ring::signature::RsaPublicKeyComponents { n, e }
                .verify(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    input,
                    signature,
                )
                .map_err(|_| BootstrapCredentialError::Rejected),
        }
    }
}
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
}
struct Keys {
    values: BTreeMap<String, Key>,
    refreshed: Option<Instant>,
}

/// Configured bootstrap credential verifier, activated before store admission.
pub struct BootstrapCredentialVerifier {
    issuer: String,
    source: Arc<dyn IssuerKeySource>,
    keys: Mutex<Keys>,
}
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenHeader {
    alg: Algorithm,
    kid: String,
    typ: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn valid(&self) -> bool {
        match self {
            Self::One(value) => value == AUDIENCE,
            Self::Many(values) => values.len() == 1 && values[0] == AUDIENCE,
        }
    }
}
#[derive(Deserialize)]
struct NamedObject {
    name: String,
    uid: String,
}
#[derive(Deserialize)]
struct PodClaims {
    namespace: String,
    pod: NamedObject,
    serviceaccount: NamedObject,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    sub: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    #[serde(rename = "kubernetes.io")]
    kubernetes: PodClaims,
}
// Retain only verified public validity bounds across issuer awaits. Never retain
// the bearer token in a startup session or deserialize a verification witness.
pub(super) struct VerifiedBootstrapCredential {
    earliest: Timestamp,
    issued: Timestamp,
    latest: Timestamp,
}
impl VerifiedBootstrapCredential {
    pub(super) fn revalidate(
        &self,
        interval: AuthenticationTimeInterval,
    ) -> Result<(), BootstrapCredentialError> {
        if !interval.is_within(self.earliest, self.latest)
            || !interval.is_within(self.issued, self.latest)
        {
            return Err(BootstrapCredentialError::AuthTimeUnavailable);
        }
        Ok(())
    }
}
impl BootstrapCredentialVerifier {
    /// Preflight fixed issuer discovery and keys; no privileged fallback exists.
    pub async fn activate(
        issuer: String,
        jwks_uri: String,
        source: Arc<dyn IssuerKeySource>,
    ) -> Result<Self, BootstrapCredentialError> {
        if !configured_https(&issuer) || !configured_https(&jwks_uri) {
            return Err(BootstrapCredentialError::Rejected);
        }
        let initialize = || async {
            let discovery = source.discovery().await?;
            if discovery.len() > 65536 {
                return Err(BootstrapCredentialError::Rejected);
            }
            let discovery: Discovery = serde_json::from_slice(&discovery)
                .map_err(|_| BootstrapCredentialError::Rejected)?;
            if discovery.issuer != issuer || discovery.jwks_uri != jwks_uri {
                return Err(BootstrapCredentialError::Rejected);
            }
            read_keys(source.as_ref()).await
        };
        let mut attempt = 0;
        let keys = loop {
            match timeout(SOURCE_DEADLINE, initialize())
                .await
                .unwrap_or(Err(BootstrapCredentialError::Unavailable))
            {
                Ok(keys) => break keys,
                Err(BootstrapCredentialError::Unavailable) if attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        };
        Ok(Self {
            issuer,
            source,
            keys: Mutex::new(Keys {
                values: keys,
                refreshed: None,
            }),
        })
    }
    pub(super) async fn verify(
        &self,
        token: &[u8],
        observation: &BootObservation,
        interval: AuthenticationTimeInterval,
    ) -> Result<VerifiedBootstrapCredential, BootstrapCredentialError> {
        let reject = || BootstrapCredentialError::Rejected;
        if token.is_empty() || token.len() > 4096 || !token.is_ascii() {
            return Err(reject());
        }
        let token = std::str::from_utf8(token).map_err(|_| reject())?;
        let mut parts = token.split('.');
        let header = parts.next().ok_or_else(reject)?;
        let claims = parts.next().ok_or_else(reject)?;
        let signature = parts.next().ok_or_else(reject)?;
        if parts.next().is_some() || header.len() > 1024 {
            return Err(reject());
        }
        let header: TokenHeader =
            serde_json::from_slice(&canonical_base64(header)?).map_err(|_| reject())?;
        let claims = zeroize::Zeroizing::new(canonical_base64(claims)?);
        let signature = canonical_base64(signature)?;
        if header.kid.is_empty()
            || header.kid.len() > 256
            || header.typ.as_deref().is_some_and(|value| value != "JWT")
        {
            return Err(reject());
        }
        // Verify the exact compact-JWS input. A known key ID can also rotate;
        // signature failures and unknown IDs share the same refresh rate limit.
        let input = token.rsplit_once('.').ok_or_else(reject)?.0;
        {
            let mut keys = self.keys.lock().await;
            let verify = |keys: &Keys| {
                let key = keys.values.get(&header.kid).ok_or_else(reject)?;
                if header.alg != key.algorithm() {
                    return Err(reject());
                }
                key.verify(input.as_bytes(), &signature)
            };
            if let Err(error) = verify(&keys) {
                let now = Instant::now();
                if keys
                    .refreshed
                    .is_none_or(|last| now.duration_since(last) >= REFRESH_INTERVAL)
                {
                    keys.refreshed = Some(now);
                    keys.values = timeout(SOURCE_DEADLINE, read_keys(self.source.as_ref()))
                        .await
                        .map_err(|_| BootstrapCredentialError::Unavailable)??;
                    verify(&keys)?;
                } else {
                    return Err(error);
                }
            }
        }
        let claims: Claims = serde_json::from_slice(&claims).map_err(|_| reject())?;
        if claims.iss != self.issuer
            || !claims.aud.valid()
            || claims.sub
                != format!(
                    "system:serviceaccount:{}:{}",
                    observation.namespace, observation.service_account
                )
            || claims.kubernetes.namespace != observation.namespace
            || claims.kubernetes.pod.name != observation.pod_name
            || claims.kubernetes.serviceaccount.name != observation.service_account
            || !same_uid(&claims.kubernetes.pod.uid, &observation.pod_uid)
            || !same_uid(
                &claims.kubernetes.serviceaccount.uid,
                &observation.service_account_uid,
            )
            || claims.exp <= claims.nbf
            || claims.exp <= claims.iat
        {
            return Err(reject());
        }
        let timestamp =
            |seconds| time::OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| reject());
        let earliest = Timestamp::from_offset_datetime(timestamp(claims.nbf)?);
        let issued = Timestamp::from_offset_datetime(timestamp(claims.iat)?);
        let end = timestamp(claims.exp)?
            .checked_sub(time::Duration::nanoseconds(1))
            .ok_or_else(reject)?;
        let latest = Timestamp::from_offset_datetime(end);
        let verified = VerifiedBootstrapCredential {
            earliest,
            issued,
            latest,
        };
        verified.revalidate(interval)?;
        Ok(verified)
    }
}
fn configured_https(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() <= 2048
        && value.len() > 8
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && !value.contains(['@', '#', '?'])
}
fn same_uid(value: &str, expected: &[u8; 16]) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|uid| uid.as_bytes() == expected && uid.to_string() == value)
}
fn canonical_base64(value: &str) -> Result<Vec<u8>, BootstrapCredentialError> {
    if value.is_empty() {
        return Err(BootstrapCredentialError::Rejected);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BootstrapCredentialError::Rejected)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(BootstrapCredentialError::Rejected);
    }
    Ok(decoded)
}
async fn read_keys(
    source: &dyn IssuerKeySource,
) -> Result<BTreeMap<String, Key>, BootstrapCredentialError> {
    let bytes = source.jwks().await?;
    if bytes.len() > 65536 {
        return Err(BootstrapCredentialError::Rejected);
    }
    let keys: JwkSet =
        serde_json::from_slice(&bytes).map_err(|_| BootstrapCredentialError::Rejected)?;
    if keys.keys.is_empty() || keys.keys.len() > 32 {
        return Err(BootstrapCredentialError::Rejected);
    }
    let mut result = BTreeMap::new();
    for key in keys.keys {
        if key.usage.as_deref().is_some_and(|usage| usage != "sig")
            || key
                .key_ops
                .as_ref()
                .is_some_and(|ops| ops.len() != 1 || ops[0] != "verify")
        {
            continue;
        }
        let required = |value: Option<String>| value.ok_or(BootstrapCredentialError::Rejected);
        let verification = match (key.kty.as_str(), key.alg.as_deref()) {
            ("EC", None | Some("ES256")) if key.crv.as_deref() == Some("P-256") => {
                let x = canonical_base64(&required(key.x)?)?;
                let y = canonical_base64(&required(key.y)?)?;
                if x.len() != 32 || y.len() != 32 {
                    return Err(BootstrapCredentialError::Rejected);
                }
                let mut point = [0; 65];
                point[0] = 4;
                point[1..33].copy_from_slice(&x);
                point[33..].copy_from_slice(&y);
                Key::Ec(
                    VerifyingKey::from_sec1_bytes(&point)
                        .map_err(|_| BootstrapCredentialError::Rejected)?,
                )
            }
            ("RSA", None | Some("RS256")) => {
                let n = canonical_base64(&required(key.n)?)?;
                let e = canonical_base64(&required(key.e)?)?;
                if !(256..=512).contains(&n.len())
                    || n[0] < 128
                    || n[n.len() - 1] & 1 == 0
                    || e.is_empty()
                    || e.len() > 4
                    || e[0] == 0
                {
                    return Err(BootstrapCredentialError::Rejected);
                }
                let exponent = e
                    .iter()
                    .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
                if exponent < 3 || exponent & 1 == 0 {
                    return Err(BootstrapCredentialError::Rejected);
                }
                Key::Rsa { n, e }
            }
            _ => continue,
        };
        let kid = key
            .kid
            .filter(|kid| !kid.is_empty() && kid.len() <= 256)
            .ok_or(BootstrapCredentialError::Rejected)?;
        if result.insert(kid, verification).is_some() {
            return Err(BootstrapCredentialError::Rejected);
        }
    }
    if result.is_empty() {
        return Err(BootstrapCredentialError::Rejected);
    }
    Ok(result)
}
