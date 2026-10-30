use opc_sbi::auth::{
    SbiAuth, SbiAuthError, SbiAuthRequest, SbiJwtValidator, SbiPeer, SbiTokenProfile,
};
use opc_sbi::headers::{BearerToken, SbiHeaders};
use opc_sbi::testkit::{test_private_key_pem, MockJwksResolver, TEST_KID};
use opc_types::{NfInstanceId, NfType, TenantId};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

const NRF: &str = "39a24027-6bab-4d15-a759-b64c2aa78aee";
const CONSUMER: &str = "b570c2a0-27dc-4ce6-8cd2-20d17d82c8bb";
const PRODUCER: &str = "d08cc065-c571-4614-8ef1-6d43e62a0067";

fn validator(audience: &str) -> SbiJwtValidator {
    SbiJwtValidator::new(
        Arc::new(MockJwksResolver::new()),
        Duration::from_secs(60),
        audience.into(),
        NRF.into(),
        true,
        false,
    )
    .with_token_profile(SbiTokenProfile::NrfAccessToken)
    .with_nrf_audience(NfType::amf(), NfInstanceId::new(PRODUCER).unwrap())
    .unwrap()
}

fn claims() -> Value {
    json!({"iss":NRF,"sub":CONSUMER,"aud":"AMF","scope":"namf-comm",
        "exp":jsonwebtoken::get_current_timestamp()+3600})
}

fn request(claims: &Value) -> SbiAuthRequest {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(test_private_key_pem().as_bytes()).unwrap();
    let token = jsonwebtoken::encode(&header, claims, &key).unwrap();
    SbiAuthRequest {
        method: http::Method::GET,
        path: "/namf-comm/v1/test".into(),
        headers: SbiHeaders::default(),
        bearer_token: Some(BearerToken::new(token).unwrap()),
        peer: SbiPeer {
            spiffe: None,
            nf_instance_id: Some(NfInstanceId::new(CONSUMER).unwrap()),
            nf_type: Some(NfType::new("smf").unwrap()),
            tenant: TenantId::new("tenant-a").unwrap(),
            plmn: None,
            snssai: None,
        },
    }
}

#[tokio::test]
async fn nrf_uuid_tokens_without_nbf_bind_to_transport_peer() {
    let request = request(&claims());
    let context = validator("AMF").authorize(&request).await.unwrap();
    assert_eq!(context.peer, request.peer);
    assert_eq!(context.scopes, ["namf-comm"]);
}

#[tokio::test]
async fn nrf_uuid_tokens_with_nbf_and_instance_audience_arrays_are_supported() {
    let mut claims = claims();
    claims["nbf"] = json!(jsonwebtoken::get_current_timestamp() - 10);
    claims["aud"] = json!([PRODUCER, "c6ed1b94-9c5b-43b5-b72a-a0ed58f8ba43"]);
    validator(PRODUCER)
        .authorize(&request(&claims))
        .await
        .unwrap();
}

#[tokio::test]
async fn review_nrf_producer_accepts_type_and_instance_audience_forms() {
    let validator = validator("AMF");
    for audience in [
        json!("AMF"),
        json!([PRODUCER]),
        json!(["c6ed1b94-9c5b-43b5-b72a-a0ed58f8ba43", PRODUCER]),
    ] {
        let mut claims = claims();
        claims["aud"] = audience;
        assert!(validator.authorize(&request(&claims)).await.is_ok());
    }
}

#[tokio::test]
async fn nrf_tokens_reject_wrong_claims_and_missing_transport_binding() {
    let validator = validator("AMF");
    for (field, value) in [
        ("iss", json!(PRODUCER)),
        ("sub", json!(PRODUCER)),
        ("sub", json!("not-a-uuid")),
        ("aud", json!("SMF")),
        ("aud", json!(["c6ed1b94-9c5b-43b5-b72a-a0ed58f8ba43"])),
        ("aud", json!(PRODUCER)),
        ("aud", json!(["AMF"])),
        ("aud", json!([PRODUCER, "not-a-uuid"])),
        ("aud", json!([PRODUCER, 1])),
        ("aud", json!([])),
        ("exp", json!(jsonwebtoken::get_current_timestamp() - 3600)),
        ("nbf", json!(jsonwebtoken::get_current_timestamp() + 3600)),
        ("nbf", Value::Null),
        ("scope", json!("namf-mt")),
        ("scope", json!("namf-comm\nnamf-mt")),
        ("scope", json!("")),
        ("sub", json!(CONSUMER.replace('-', ""))),
    ] {
        let mut claims = claims();
        claims[field] = value;
        assert!(
            validator.authorize(&request(&claims)).await.is_err(),
            "must reject {field}"
        );
    }
    for field in ["iss", "sub", "aud", "exp", "scope"] {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(field);
        assert!(
            validator.authorize(&request(&claims)).await.is_err(),
            "must require {field}"
        );
    }
    let mut request = request(&claims());
    request.peer.nf_instance_id = None;
    assert_eq!(
        validator.authorize(&request).await.unwrap_err(),
        SbiAuthError::MissingPeerBinding
    );
    request.peer.nf_instance_id = Some(NfInstanceId::new(CONSUMER).unwrap());
    request.peer.nf_type = None;
    assert_eq!(
        validator.authorize(&request).await.unwrap_err(),
        SbiAuthError::MissingPeerBinding
    );
}

#[tokio::test]
async fn token_profiles_cannot_be_selected_by_untrusted_claims() {
    let jwt_svid = validator("AMF").with_token_profile(SbiTokenProfile::JwtSvid);
    let mut uuid_claims = claims();
    uuid_claims["nbf"] = json!(jsonwebtoken::get_current_timestamp() - 10);
    assert!(jwt_svid.authorize(&request(&uuid_claims)).await.is_err());
    let mut spiffe_claims = claims();
    spiffe_claims["sub"] = json!(format!(
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/smf/nf/smf/instance/{CONSUMER}"
    ));
    assert!(validator("AMF")
        .authorize(&request(&spiffe_claims))
        .await
        .is_err());
    spiffe_claims["nbf"] = json!(jsonwebtoken::get_current_timestamp() - 10);
    assert!(jwt_svid.authorize(&request(&spiffe_claims)).await.is_ok());
    spiffe_claims["aud"] = json!([PRODUCER]);
    assert!(
        jwt_svid.authorize(&request(&spiffe_claims)).await.is_err(),
        "NRF audience configuration must not broaden JWT-SVID audiences"
    );
}

#[tokio::test]
async fn nrf_audiences_require_trusted_type_and_instance_configuration() {
    let validator = SbiJwtValidator::new(
        Arc::new(MockJwksResolver::new()),
        Duration::from_secs(60),
        "AMF".into(),
        NRF.into(),
        true,
        false,
    )
    .with_token_profile(SbiTokenProfile::NrfAccessToken);
    assert!(matches!(
        validator.authorize(&request(&claims())).await,
        Err(SbiAuthError::Internal { .. })
    ));
    assert!(validator
        .with_nrf_audience(NfType::amf(), NfInstanceId::new("not-a-uuid").unwrap())
        .is_err());
}

#[tokio::test]
async fn nrf_profile_requires_signatures_even_with_dev_bypass_enabled() {
    let validator = SbiJwtValidator::new(
        Arc::new(MockJwksResolver::new()),
        Duration::from_secs(60),
        "AMF".into(),
        NRF.into(),
        false,
        true,
    )
    .with_token_profile(SbiTokenProfile::NrfAccessToken)
    .with_nrf_audience(NfType::amf(), NfInstanceId::new(PRODUCER).unwrap())
    .unwrap();
    let mut req = request(&claims());
    let mut token = req
        .bearer_token
        .as_ref()
        .unwrap()
        .expose()
        .as_bytes()
        .to_vec();
    let signature = token.iter().rposition(|c| *c == b'.').unwrap() + 1;
    token[signature] = if token[signature] == b'A' { b'B' } else { b'A' };
    req.bearer_token = Some(BearerToken::new(String::from_utf8(token).unwrap()).unwrap());
    assert!(validator.authorize(&req).await.is_err());
    req.bearer_token = Some(BearerToken::new("mock-token-test").unwrap());
    assert!(validator.authorize(&req).await.is_err());
}
