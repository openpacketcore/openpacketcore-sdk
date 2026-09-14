//! Shared original workload encryption, requests and exact validators.

use super::*;

pub(super) fn key(index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sdk-702-v2-qualification").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("unique-transition-{index}"))
            .try_into()
            .expect("stable ID"),
    }
}

pub(super) fn owner() -> OwnerId {
    OwnerId::new("sdk-702-v2-qualification-owner").expect("owner")
}

pub(super) fn sealing_provider() -> MemoryKeyProvider {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("sdk-702-v2-qualification-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("sdk-702-v2-qualification").expect("tenant"),
            Zeroizing::new([0x72; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("active session key");
    provider
}

pub(super) async fn create_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    key: SessionKey,
    fence: FenceToken,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let owner = owner();
    let lease =
        FencedTransitionLease::acquire(key.clone(), owner.clone(), fence, Duration::from_secs(60))
            .expect("acquire request");
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(fence.get() + 1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification transition payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("self-authenticating request")
}

pub(super) async fn renew_update_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    previous: &FencedTransitionOutcome,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let key = previous.lease().key().clone();
    let owner = previous.lease().owner().clone();
    let fence = previous.lease().fence();
    let expected_generation = previous.committed_generation();
    let generation = expected_generation
        .next()
        .expect("qualification generation has headroom");
    let lease = FencedTransitionLease::renew(previous.lease().clone(), Duration::from_secs(60))
        .expect("renew request");
    let mut record = StoredSessionRecord {
        key,
        generation,
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification-update")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification update payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::update(expected_generation, record),
    )
    .expect("self-authenticating update request")
}

/// Validate the semantic result shape in addition to V2's self-authenticating
/// request/result correlation. The release workload has only create and
/// renewal-update operations, so accepting another mutation result here would
/// make the evidence claim false even if its generic response were valid.
pub(super) fn is_exact_qualified_v2_success(
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
) -> bool {
    if !outcome.matches_v2_request(request) {
        return false;
    }
    match (request.lease(), request.mutation()) {
        (FencedTransitionLease::Acquire { .. }, FencedTransitionMutation::Create { record }) => {
            outcome.mutation() == FencedTransitionMutationResult::Created
                && outcome.committed_generation() == record.generation
        }
        (
            FencedTransitionLease::Renew { lease: prior, .. },
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            },
        ) => {
            outcome.mutation() == FencedTransitionMutationResult::Updated
                && outcome.lease().key() == prior.key()
                && outcome.lease().owner() == prior.owner()
                && outcome.lease().fence() == prior.fence()
                && outcome.lease().acquired_at() == prior.acquired_at()
                && outcome.lease().credential_id() == prior.credential_id()
                && expected_generation.next() == Some(record.generation)
                && outcome.committed_generation() == record.generation
        }
        _ => false,
    }
}

pub(super) fn assert_exact_qualified_v2_success(
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
) {
    assert!(
        is_exact_qualified_v2_success(request, outcome),
        "every qualified V2 outcome must exactly match its V2 request"
    );
}

pub(super) fn assert_exact_qualified_update_request(
    previous: &FencedTransitionOutcome,
    request: &FencedTransitionV2Request,
) {
    match (request.lease(), request.mutation()) {
        (
            FencedTransitionLease::Renew { lease, .. },
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            },
        ) => {
            assert_eq!(lease, previous.lease());
            assert_eq!(*expected_generation, previous.committed_generation());
            assert_eq!(record.key, *previous.lease().key());
            assert_eq!(record.owner, *previous.lease().owner());
            assert_eq!(record.fence, previous.lease().fence());
            assert_eq!(
                record.generation,
                previous
                    .committed_generation()
                    .next()
                    .expect("qualified prior generation has headroom")
            );
        }
        _ => panic!("qualified update request must renew the exact prior outcome"),
    }
}

pub(super) fn request_with_changed_body(
    request: &FencedTransitionV2Request,
) -> FencedTransitionV2Request {
    let mut encoded = serde_json::to_value(request).expect("serialize retained V2 request");
    let mutation = encoded
        .get_mut("mutation")
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 request mutation");
    let mutation_body = if mutation.contains_key("create") {
        mutation.get_mut("create")
    } else {
        mutation.get_mut("update")
    };
    let record = mutation_body
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mutation| mutation.get_mut("record"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 create or update request record");
    record.insert(
        "state_type".to_owned(),
        serde_json::Value::String("sdk-702-v2-qualification-altered".to_owned()),
    );
    serde_json::from_value(encoded).expect("deserialize altered V2 request")
}
