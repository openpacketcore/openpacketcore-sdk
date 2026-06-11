//! JWT-SVID validation and client token acquisition (RFC 007 §9.2–9.3).
//!
//! Server side: `SbiJwtValidator` implements `SbiAuth` by verifying RS256
//! JWT-SVIDs against a JWKS fetched through a `JwksResolver` and cached
//! fail-closed in a `JwksCache`. Peer identity (tenant, NF type, instance)
//! is derived from the SPIFFE ID in the token's `sub` claim.
//!
//! Client side: `ClientTokenCache` caches tokens obtained from a
//! `TokenProvider` per normalized scope set, refreshing shortly before
//! expiry.

use crate::auth::{SbiAuth, SbiAuthContext, SbiAuthError, SbiAuthRequest, SbiPeer};
use crate::headers::BearerToken;
use crate::redact::sanitize_error_message;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use opc_types::{NfInstanceId, NfType, SpiffeId, TenantId};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Single JSON Web Key (RFC 7517) used for JWT-SVID signature verification.
///
/// Only the RSA subset needed for RS256 validation is modeled; keys with
/// other types or algorithms are skipped during lookup, never rejected
/// loudly.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (`kty`). Only `"RSA"` keys are usable for validation here.
    pub kty: String,
    /// Key ID (`kid`) matched against the JWT header's `kid`; keys without
    /// one can never be selected.
    pub kid: Option<String>,
    /// Declared algorithm (`alg`). If present it must be `"RS256"` for the
    /// key to be eligible; an absent `alg` is treated as RS256-compatible.
    pub alg: Option<String>,
    /// RSA public modulus (`n`), base64url-encoded per RFC 7518 §6.3.
    pub n: Option<String>, // RSA modulus
    /// RSA public exponent (`e`), base64url-encoded per RFC 7518 §6.3.
    pub e: Option<String>, // RSA exponent
}

/// JSON Web Key Set (RFC 7517 §5): the document fetched from the issuer's
/// JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    /// All published keys; lookup filters by `kid`, RSA key type, and RS256
    /// compatibility.
    pub keys: Vec<Jwk>,
}

/// Resolver trait for fetching JWKS dynamically.
#[async_trait]
pub trait JwksResolver: Send + Sync {
    /// Fetch the issuer's current key set (e.g. over HTTPS).
    ///
    /// Errors propagate into `JwksCache::get_decoding_key`, which reacts by
    /// invalidating its cache (fail-closed); the error string is sanitized
    /// before reaching any caller-visible surface, but implementations
    /// should still avoid embedding secrets or endpoints in it.
    async fn fetch_jwks(&self) -> Result<Jwks, String>;
}

/// In-memory cache for JWKS with TTL and fail-closed refresh behavior.
pub struct JwksCache {
    resolver: Arc<dyn JwksResolver>,
    ttl: Duration,
    cached: Mutex<Option<(Jwks, Instant)>>,
}

impl JwksCache {
    /// Create an empty cache that refreshes through `resolver` and serves a
    /// fetched key set for `ttl` before refetching. The first
    /// `get_decoding_key` call always hits the resolver.
    pub fn new(resolver: Arc<dyn JwksResolver>, ttl: Duration) -> Self {
        Self {
            resolver,
            ttl,
            cached: Mutex::new(None),
        }
    }

    /// Return the RS256 decoding key for the given JWT `kid`.
    ///
    /// Serves from the cached JWKS while it is within TTL; on miss or
    /// expiry the resolver is queried again. If the refresh fails the
    /// entire cache is dropped (fail-closed — no token can validate against
    /// a stale key set) and the `jwks_refresh_failure` outcome is counted
    /// in the `sbi_oauth_validation_total` metric. A successful refresh
    /// that still lacks the `kid` is also an error (covers rotated or
    /// unknown key IDs).
    pub async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, String> {
        let now = Instant::now();
        // 1. Check if cached and still fresh
        {
            let lock = self.cached.lock().unwrap();
            if let Some((ref jwks, expiry)) = *lock {
                if now < expiry {
                    if let Some(key) = find_key_in_jwks(jwks, kid) {
                        return Ok(key);
                    }
                }
            }
        }

        // 2. Fetch new JWKS on miss/expiry
        let jwks = match self.resolver.fetch_jwks().await {
            Ok(jwks) => jwks,
            Err(e) => {
                // Fail-closed refresh: invalidate completely if refresh fails
                let mut lock = self.cached.lock().unwrap();
                *lock = None;
                // Increment refresh failure metric
                opc_redaction::metrics::METRICS
                    .sbi_oauth_validation_total
                    .lock()
                    .unwrap()
                    .entry(("error".to_string(), "jwks_refresh_failure".to_string()))
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                return Err(format!(
                    "JWKS refresh failed: {}",
                    sanitize_error_message(e)
                ));
            }
        };

        let key = find_key_in_jwks(&jwks, kid)
            .ok_or_else(|| "signature key not found in refreshed JWKS".to_string())?;

        // Update cache
        let mut lock = self.cached.lock().unwrap();
        *lock = Some((jwks, now + self.ttl));
        Ok(key)
    }
}

fn find_key_in_jwks(jwks: &Jwks, kid: &str) -> Option<DecodingKey> {
    for key in &jwks.keys {
        let algorithm_allowed = match key.alg.as_deref() {
            Some(alg) => alg == "RS256",
            None => true,
        };
        if key.kid.as_deref() == Some(kid) && key.kty == "RSA" && algorithm_allowed {
            if let (Some(n), Some(e)) = (&key.n, &key.e) {
                if let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) {
                    return Some(decoding_key);
                }
            }
        }
    }
    None
}

/// Claim set of a JWT-SVID as validated by `SbiJwtValidator` (RFC 7519
/// registered claims plus the OAuth2 `scope` claim).
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct SvidClaims {
    /// Issuer (`iss`); must equal the validator's expected issuer exactly.
    pub iss: String,
    /// Subject (`sub`): the workload's SPIFFE ID. The validator parses
    /// tenant, NF type, and NF instance ID out of its path segments.
    pub sub: String,
    /// Audience (`aud`); either a single string or an array of strings per
    /// RFC 7519 §4.1.3 — the expected audience must match or be contained.
    pub aud: serde_json::Value,
    /// Expiry (`exp`) in **seconds** since the Unix epoch; mandatory, and
    /// tokens past it are denied.
    pub exp: u64,
    /// Not-before (`nbf`) in seconds since the Unix epoch. Optional in the
    /// struct, but the validator requires it and rejects tokens used early.
    pub nbf: Option<u64>,
    /// OAuth2 scopes as a single **space-delimited** string (e.g.
    /// `"nnrf-disc nnrf-nfm"`); split into individual scopes after
    /// validation.
    pub scope: Option<String>,
}

/// Production JWT-SVID Validator
pub struct SbiJwtValidator {
    jwks_cache: JwksCache,
    expected_aud: String,
    expected_iss: String,
    production_mode: bool,
    bypass_verification_in_dev: bool,
}

impl SbiJwtValidator {
    /// Build a validator that verifies RS256 JWT-SVIDs against keys fetched
    /// through `resolver` (cached for `jwks_ttl`) and requires the given
    /// audience and issuer, plus mandatory `exp`/`nbf` claims.
    ///
    /// `bypass_verification_in_dev` enables a dev/test-only shortcut: tokens
    /// prefixed `mock-token-` (as issued by the testkit `MockNrf`) are
    /// accepted without signature verification and yield a fixed mock AMF
    /// peer. The bypass is **ignored whenever `production_mode` is true**,
    /// so it cannot weaken a production deployment.
    pub fn new(
        resolver: Arc<dyn JwksResolver>,
        jwks_ttl: Duration,
        expected_aud: String,
        expected_iss: String,
        production_mode: bool,
        bypass_verification_in_dev: bool,
    ) -> Self {
        Self {
            jwks_cache: JwksCache::new(resolver, jwks_ttl),
            expected_aud,
            expected_iss,
            production_mode,
            bypass_verification_in_dev,
        }
    }
}

#[async_trait]
impl SbiAuth for SbiJwtValidator {
    async fn authorize(&self, request: &SbiAuthRequest) -> Result<SbiAuthContext, SbiAuthError> {
        let token = request
            .bearer_token
            .as_ref()
            .ok_or(SbiAuthError::MissingBearerToken)?;

        // 1. Unsafe dev/test bypass (never in Production mode)
        if !self.production_mode
            && self.bypass_verification_in_dev
            && token.expose().starts_with("mock-token-")
        {
            // Return a mock context for testing
            let spiffe_str =
                "spiffe://example.test/tenant/default/ns/core/sa/amf/nf/amf/instance/mock-instance"
                    .to_string();
            let spiffe = SpiffeId::new(spiffe_str).ok();
            let peer = SbiPeer {
                spiffe,
                nf_instance_id: NfInstanceId::new("mock-instance").ok(),
                nf_type: NfType::new("amf").ok(),
                tenant: TenantId::new("default").unwrap(),
                plmn: None,
                snssai: None,
            };
            // Increment allow metric
            opc_redaction::metrics::METRICS
                .sbi_oauth_validation_total
                .lock()
                .unwrap()
                .entry(("allow".to_string(), "bypass_dev".to_string()))
                .and_modify(|c| *c += 1)
                .or_insert(1);
            return Ok(SbiAuthContext {
                peer,
                scopes: vec!["nnrf-disc".into()],
                access_token: Some(token.clone()),
            });
        }

        // 2. Decode header to extract kid
        let header = decode_header(token.expose()).map_err(|_| SbiAuthError::Denied {
            reason: "invalid token header".to_string(),
        })?;

        let kid = header.kid.ok_or_else(|| SbiAuthError::Denied {
            reason: "missing kid in token header".into(),
        })?;

        // 3. Retrieve signature decoding key (fails closed)
        let decoding_key =
            self.jwks_cache
                .get_decoding_key(&kid)
                .await
                .map_err(|e| SbiAuthError::Internal {
                    reason: sanitize_error_message(format!("failed to get signature key: {}", e)),
                })?;

        // 4. Validate signature, issuer, and expiry
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.expected_aud]);
        validation.set_issuer(&[&self.expected_iss]);
        validation.validate_nbf = true;
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("nbf".to_string());

        let token_data =
            decode::<SvidClaims>(token.expose(), &decoding_key, &validation).map_err(|_| {
                // Increment deny metric
                opc_redaction::metrics::METRICS
                    .sbi_oauth_validation_total
                    .lock()
                    .unwrap()
                    .entry(("deny".to_string(), "validation_failed".to_string()))
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                SbiAuthError::Denied {
                    reason: "token validation failed".to_string(),
                }
            })?;

        let claims = token_data.claims;

        // 5. Verify Audience
        if !validate_audience(&claims.aud, &self.expected_aud) {
            return Err(SbiAuthError::Denied {
                reason: "audience mismatch".into(),
            });
        }

        // 6. Parse SPIFFE ID from Subject claim
        let spiffe = SpiffeId::new(&claims.sub).map_err(|_| SbiAuthError::Denied {
            reason: "invalid spiffe id".to_string(),
        })?;

        let (tenant_str, nf_kind_str, instance_id_str) = parse_spiffe_id_segments(&spiffe)
            .ok_or_else(|| SbiAuthError::Denied {
                reason: "SPIFFE ID layout mismatch".into(),
            })?;

        let tenant = TenantId::new(tenant_str).map_err(|_| SbiAuthError::Denied {
            reason: "invalid tenant".to_string(),
        })?;
        let nf_type = NfType::new(nf_kind_str).map_err(|_| SbiAuthError::Denied {
            reason: "invalid nf_type".to_string(),
        })?;
        let nf_instance_id =
            NfInstanceId::new(instance_id_str).map_err(|_| SbiAuthError::Denied {
                reason: "invalid nf_instance_id".to_string(),
            })?;

        let peer = SbiPeer {
            spiffe: Some(spiffe),
            nf_instance_id: Some(nf_instance_id),
            nf_type: Some(nf_type),
            tenant,
            plmn: None,
            snssai: None,
        };

        let scopes = claims
            .scope
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        // Increment allow metric
        opc_redaction::metrics::METRICS
            .sbi_oauth_validation_total
            .lock()
            .unwrap()
            .entry(("allow".to_string(), "success".to_string()))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        Ok(SbiAuthContext {
            peer,
            scopes,
            access_token: Some(token.clone()),
        })
    }
}

fn validate_audience(aud_value: &serde_json::Value, expected_aud: &str) -> bool {
    match aud_value {
        serde_json::Value::String(s) => s == expected_aud,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
        _ => false,
    }
}

fn parse_spiffe_id_segments(spiffe_id: &SpiffeId) -> Option<(String, String, String)> {
    let path = spiffe_id.path();
    let mut seg = path.trim_start_matches('/').split('/');
    let mut first = seg.next();
    if first == Some("trust-domain") {
        first = seg.next();
    }
    if first != Some("tenant") {
        return None;
    }
    let tenant = seg.next()?.to_string();
    if seg.next() != Some("ns") {
        return None;
    }
    let _ns = seg.next()?;
    if seg.next() != Some("sa") {
        return None;
    }
    let _sa = seg.next()?;
    if seg.next() != Some("nf") {
        return None;
    }
    let nf_kind = seg.next()?.to_string();
    if seg.next() != Some("instance") {
        return None;
    }
    let instance_id = seg.next()?.to_string();
    if seg.next().is_some() {
        return None;
    }
    Some((tenant, nf_kind, instance_id))
}

/// Token Provider trait for client token acquisition
#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Obtain a fresh access token granting the requested scopes, e.g. via
    /// the NRF AccessToken service (TS 29.510) or another OAuth2 server.
    ///
    /// Implementations should return an error rather than a token with
    /// fewer scopes than requested; the error string must be free of
    /// credential material.
    async fn get_token(&self, scopes: &[String]) -> Result<BearerToken, String>;
}

/// Bounded client credentials token cache
pub struct ClientTokenCache {
    provider: Arc<dyn TokenProvider>,
    cached: Mutex<HashMap<Vec<String>, (BearerToken, Instant)>>,
    max_entries: usize,
    max_token_ttl: Duration,
}

impl ClientTokenCache {
    /// Create a cache with the default bounds: at most 100 distinct scope
    /// sets, each token assumed valid for 300 seconds after acquisition.
    pub fn new(provider: Arc<dyn TokenProvider>) -> Self {
        Self::new_with_bounds(provider, 100, Duration::from_secs(300))
    }

    /// Create a cache with explicit bounds.
    ///
    /// `max_entries` caps how many distinct (sorted, deduplicated) scope
    /// sets are cached; `max_token_ttl` is how long an acquired token is
    /// served before being treated as expired — the cache does not inspect
    /// the token's own `exp`, so keep this at or below the issuer's actual
    /// token lifetime. Values are clamped to at least 1 entry / 1 second.
    pub fn new_with_bounds(
        provider: Arc<dyn TokenProvider>,
        max_entries: usize,
        max_token_ttl: Duration,
    ) -> Self {
        Self {
            provider,
            cached: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
            max_token_ttl: max_token_ttl.max(Duration::from_secs(1)),
        }
    }

    /// Return a token granting `scopes`, from cache when possible.
    ///
    /// The scope set is validated (1–32 scopes, each non-empty, at most 128
    /// characters, no whitespace) then sorted and deduplicated so order
    /// does not fragment the cache. A cached token is reused only while
    /// more than 30 seconds of its TTL remain, refreshing proactively
    /// before expiry. When the cache is full an arbitrary entry is evicted
    /// to admit the new one. Provider failures are returned as-is; nothing
    /// stale is served.
    pub async fn get_token(&self, scopes: &[String]) -> Result<BearerToken, String> {
        if scopes.is_empty() || scopes.len() > 32 {
            return Err("invalid token scope set".to_string());
        }
        if scopes.iter().any(|scope| {
            scope.trim().is_empty() || scope.len() > 128 || scope.contains(char::is_whitespace)
        }) {
            return Err("invalid token scope set".to_string());
        }

        let mut scopes_sorted = scopes.to_vec();
        scopes_sorted.sort();
        scopes_sorted.dedup();

        let now = Instant::now();
        // Check cache with a 30-second buffer
        {
            let lock = self.cached.lock().unwrap();
            if let Some((token, expiry)) = lock.get(&scopes_sorted) {
                if now + Duration::from_secs(30) < *expiry {
                    return Ok(token.clone());
                }
            }
        }

        // Fetch new token
        let token = self.provider.get_token(scopes).await?;
        let expiry = now + self.max_token_ttl;

        let mut lock = self.cached.lock().unwrap();
        if lock.len() >= self.max_entries {
            if let Some(first_key) = lock.keys().next().cloned() {
                lock.remove(&first_key);
            }
        }
        lock.insert(scopes_sorted, (token.clone(), expiry));
        Ok(token)
    }
}
