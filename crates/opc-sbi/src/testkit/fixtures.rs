//! Token and payload fixtures for SBI auth tests.
//!
//! Ships a fixed RSA test keypair (private key for signing, public JWKS
//! components for verification) so tests can mint real RS256 JWT-SVIDs that
//! `SbiJwtValidator` accepts or rejects deterministically. The keypair is
//! test-only material committed to the repository — never deploy it.

use crate::auth::{Jwk, Jwks, JwksResolver};
use crate::problem::ProblemDetails;
use http::StatusCode;

const TEST_PRIVATE_KEY_BODY: &str = "\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2MBr6gTx9NMQ9\n\
EaDnmDdNOj8LsPgCalJ4aOJxJGSBtV6/gknSbM12y7E+Zo1afNg7PCM1WyTZhHZv\n\
/ZDPaGDkA7y5impjPb5RvmezNekY2yWx3prmgt8fFf0kLLL+ow/q46zIKMo9BC3q\n\
QjFOtmhbj8M6dWco47BChJEuiVePP7d2AHFQqUDFvDhDSk0NZVuIxEgOj8z8fclb\n\
JqqtFZOwsadItEuU1932YL39IkTD8w7C/0QHQXF1FU7xyRdzVg4mCDYxorgllhim\n\
8iyPL94QnVeHP+2elVKAkNqWeiSfRo17o3V3is3L5KmVwSWCsEaxcAy1ZkzUFx4U\n\
TH8gCiffAgMBAAECggEARq/Ab+w/n2afMwCJeQHuhviv6GXXu/wrlks/fF1933OS\n\
2OQAp3OOfmaGlOruMisZLFZnZLbBw+FooIf1rPtXCHDIwwZIw8t7cbTaAEbM81dn\n\
tyzi1cf2MNXzuxrasgBrVxvR+HEXEnhyJh9biSotsETFnwNZLJy20QAlYjRodAvB\n\
XepYbgzr28F/Rqv+Khpj7zj3xZfl+gpFnibqcElQtjniQ8LS4/75/P936lFByly0\n\
88AcyCrfPHP6CMr0SryFcd//II6bwFmO3AD8uxK6fTqZ6B0ntAP1gotTWwKAnZ5z\n\
lVE9GdLW3k8kMohkixDRGmqfqpjNqvXGHowgLTLxqQKBgQDjqVZqkWovpXeyJeiX\n\
1mCiw2PqEXRCNBaZjZEjEo1T8oMV/qiBjp+PmiFBBHdoXPSM5oddgPbS6yRrJFCP\n\
ocH3ku1ZwbztnWudV1M3zfwAywWeVXBO+hYO5m9DrPNQnAdiCoH9VJ9TknYO2DFU\n\
h/qlghWP8AelvMUg2UV0MCnTJwKBgQDM3bT2KpdWbR3wRf4dCJR5m/kyb0KUV8WK\n\
etYQSuxaggFl9K9a06pmaaTJX5GvawLiNLEzho/PvfwKROVJm4lDcB6pYzhHZMeH\n\
HraAnIp8xu2iznsoSxuxYHGzR667FV+Lu6otIBYaTS9fke1Ge0Rj0GlU4o/OZ0Ju\n\
/nJk0w+YiQKBgEioXsAcMLuMH6tnldf/v0+y9ExbzbLjVOMk31FGNny4RUXbxIO0\n\
tQ/rrPlHJ6TTJeliGYmqAxxFl5XqPRvaEEGnTsD6qAVd3F6W5CRHRUorgVuLARDz\n\
l96hhJkgtXbglSqhF+N2AnN1puAN95B25XO1FJSfkpE+sdtN/HCcfny5AoGAMjfy\n\
wRklqeDrotd1eCZ/RuQuDOfrGTP+z3hW+v1yvKj7sMNvLMOQFLS22UodCzQfK9Yg\n\
zfGhVRpMKzRCRG3lEuvsCDezNwUESCIGOLam1/lnjS4yUGlA65UpqfnbYi7WEgm5\n\
qIAiCuZ6w2GhGVLkK9eNymoTOFRlm5Gx9vcp7okCgYBmhXRi4R7CTJ7NPFzuSS5b\n\
rsufS/lgYxZbl8AejlVWjwdh1jlkCn7HujiTrt1YcV8LQW6uJjvh/sGPLG/HFxkQ\n\
UQROADFE5xEO1JlHukp28ZztJBPCV3vXMUKp8+feoA+wtUFzEaBo3WNXxEtnTCP9\n\
zbBrG2DI7u9XzIYmNzPM5g==\n";

/// Render the fixed RSA **test** private key as a PKCS#8 PEM string, for
/// signing fixture tokens. This key is public knowledge by design; it must
/// never guard real traffic.
pub fn test_private_key_pem() -> String {
    format!(
        "-----BEGIN {}-----\n{}-----END {}-----",
        "PRIVATE KEY", TEST_PRIVATE_KEY_BODY, "PRIVATE KEY"
    )
}

/// Base64url-encoded RSA modulus (`n`, RFC 7517) of the test keypair —
/// the public counterpart of `test_private_key_pem`.
pub const TEST_MODULUS_N: &str = "tjAa-oE8fTTEPRGg55g3TTo_C7D4AmpSeGjicSRkgbVev4JJ0mzNdsuxPmaNWnzYOzwjNVsk2YR2b_2Qz2hg5AO8uYpqYz2-Ub5nszXpGNslsd6a5oLfHxX9JCyy_qMP6uOsyCjKPQQt6kIxTrZoW4_DOnVnKOOwQoSRLolXjz-3dgBxUKlAxbw4Q0pNDWVbiMRIDo_M_H3JWyaqrRWTsLGnSLRLlNfd9mC9_SJEw_MOwv9EB0FxdRVO8ckXc1YOJgg2MaK4JZYYpvIsjy_eEJ1Xhz_tnpVSgJDalnokn0aNe6N1d4rNy-SplcElgrBGsXAMtWZM1BceFEx_IAon3w";
/// Base64url-encoded RSA public exponent (`e`) of the test keypair; the
/// conventional 65537.
pub const TEST_EXPONENT_E: &str = "AQAB";
/// Key ID stamped into fixture token headers and the mock JWKS; change it
/// in one place to simulate an unknown-`kid` validation failure.
pub const TEST_KID: &str = "test-key-id";

/// Mock JWKS Resolver providing the public components of the test key.
pub struct MockJwksResolver {
    jwks: Jwks,
}

impl MockJwksResolver {
    /// Resolver whose JWKS contains exactly one RS256 key: the test key
    /// under `TEST_KID`. `fetch_jwks` always succeeds, so it cannot
    /// exercise fail-closed refresh paths — use a custom resolver for
    /// those.
    pub fn new() -> Self {
        Self {
            jwks: Jwks {
                keys: vec![Jwk {
                    kty: "RSA".to_string(),
                    kid: Some(TEST_KID.to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some(TEST_MODULUS_N.to_string()),
                    e: Some(TEST_EXPONENT_E.to_string()),
                }],
            },
        }
    }
}

impl Default for MockJwksResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl JwksResolver for MockJwksResolver {
    async fn fetch_jwks(&self) -> Result<Jwks, String> {
        Ok(self.jwks.clone())
    }
}

/// Generate a structurally valid and cryptographic signed test token.
///
/// RS256-signed with the fixture private key under `TEST_KID`, expiring
/// `expire_in_secs` seconds from now (negative for an already-expired
/// token) with `nbf` backdated 10 seconds so the token is immediately
/// usable.
pub fn generate_test_token(
    sub: &str,
    aud: &str,
    iss: &str,
    scopes: Option<String>,
    expire_in_secs: i64,
) -> String {
    generate_test_token_with_nbf_offset(sub, aud, iss, scopes, expire_in_secs, -10)
}

/// Like `generate_test_token` but with an explicit `nbf` offset in seconds
/// relative to now: pass a positive offset to mint a not-yet-valid token
/// and exercise `nbf` rejection in the validator.
pub fn generate_test_token_with_nbf_offset(
    sub: &str,
    aud: &str,
    iss: &str,
    scopes: Option<String>,
    expire_in_secs: i64,
    nbf_offset_secs: i64,
) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let private_key_pem = test_private_key_pem();
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
    let now = jsonwebtoken::get_current_timestamp();
    let exp = (now as i64 + expire_in_secs) as u64;
    let nbf = (now as i64 + nbf_offset_secs) as u64;

    let claims = crate::auth::SvidClaims {
        iss: iss.to_string(),
        sub: sub.to_string(),
        aud: serde_json::Value::String(aud.to_string()),
        exp,
        nbf: Some(nbf),
        scope: scopes,
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());

    encode(&header, &claims, &encoding_key).unwrap()
}

/// Token fixtures for testing common access scenarios.
pub struct TokenFixtures;

impl TokenFixtures {
    /// Valid token that expires in 1 hour
    pub fn valid(sub: &str, aud: &str, iss: &str, scopes: &str) -> String {
        generate_test_token(sub, aud, iss, Some(scopes.to_string()), 3600)
    }

    /// Token that expired 1 hour ago
    pub fn expired(sub: &str, aud: &str, iss: &str) -> String {
        generate_test_token(sub, aud, iss, None, -3600)
    }

    /// Token with incorrect audience
    pub fn bad_audience(sub: &str, expected_iss: &str) -> String {
        generate_test_token(sub, "wrong-audience", expected_iss, None, 3600)
    }
}

/// Failure fixtures for testing bad or edge-case payloads.
pub struct FailureFixtures;

impl FailureFixtures {
    /// Helper to serialize a standard ProblemDetails
    pub fn problem_details(status: StatusCode, detail: &str) -> Vec<u8> {
        let mut details = ProblemDetails::new(status);
        details.detail = Some(detail.to_string());
        serde_json::to_vec(&details).unwrap()
    }

    /// Malformed ProblemDetails JSON payload (violating standard schema)
    pub fn malformed_problem_details() -> Vec<u8> {
        b"{ \"status\": \"not-a-number\", \"invalid_field\": true }".to_vec()
    }
}
