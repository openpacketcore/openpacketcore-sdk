use super::*;

const NAMESPACE: &str = "provider-availability";

fn record() -> StoredSessionRecord {
    let ReplicationOp::CompareAndSet { new_record, .. } =
        test_replication_entry(1, "provider-availability").op
    else {
        panic!("fixture must contain a record");
    };
    new_record
}

fn assert_unavailable(error: StoreError) {
    assert_eq!(
        error,
        StoreError::BackendUnavailable("session key provider unavailable".into())
    );
}

#[tokio::test]
async fn provider_unavailable_local_seal_is_retryable() {
    let provider = FailOnCallKeyProvider::new(test_provider(), 1);
    let record = record();
    let error = EncryptedSessionPayload::encrypt(&provider, &record, NAMESPACE)
        .await
        .expect_err("first key lookup is unavailable");
    assert_unavailable(error);
    assert_eq!(provider.calls(), 1);

    let encrypted = EncryptedSessionPayload::encrypt(&provider, &record, NAMESPACE)
        .await
        .expect("same record succeeds when its provider recovers");
    assert_eq!(provider.calls(), 2);
    let plaintext = encrypted
        .decrypt(
            provider.inner.as_ref(),
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            NAMESPACE,
        )
        .await
        .expect("recovered seal preserves plaintext");
    assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
}

#[tokio::test]
async fn provider_unavailable_local_unseal_is_retryable() {
    let inner = test_provider();
    let record = record();
    let encrypted = EncryptedSessionPayload::encrypt(inner.as_ref(), &record, NAMESPACE)
        .await
        .expect("prepare valid envelope");
    let provider = FailOnCallKeyProvider::new(inner, 1);
    let decrypt = || {
        encrypted.decrypt(
            &provider,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            NAMESPACE,
        )
    };
    assert_unavailable(
        decrypt()
            .await
            .expect_err("historical key lookup is unavailable"),
    );
    assert_eq!(provider.calls(), 1);
    let plaintext = decrypt().await.expect("same envelope can be retried");
    assert_eq!(provider.calls(), 2);
    assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
}

#[tokio::test]
async fn provider_unavailable_remote_seal_is_retryable() {
    let provider = FailOnCallRemoteSealProvider::new(test_remote_seal_provider(), 1);
    let record = record();
    let error = EncryptedSessionPayload::remote_seal(&provider, &record, NAMESPACE)
        .await
        .expect_err("first remote seal is unavailable");
    assert_unavailable(error);
    assert_eq!(provider.calls(), 1);

    let encrypted = EncryptedSessionPayload::remote_seal(&provider, &record, NAMESPACE)
        .await
        .expect("same record succeeds when its provider recovers");
    assert_eq!(provider.calls(), 2);
    let plaintext = encrypted
        .remote_unseal(
            provider.inner.as_ref(),
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            NAMESPACE,
        )
        .await
        .expect("recovered seal preserves plaintext");
    assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
}

#[tokio::test]
async fn provider_unavailable_remote_unseal_is_retryable() {
    let inner = test_remote_seal_provider();
    let record = record();
    let encrypted = EncryptedSessionPayload::remote_seal(inner.as_ref(), &record, NAMESPACE)
        .await
        .expect("prepare valid envelope");
    let provider = FailOnCallRemoteSealProvider::new(inner, 1);
    let unseal = || {
        encrypted.remote_unseal(
            &provider,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            NAMESPACE,
        )
    };
    assert_unavailable(
        unseal()
            .await
            .expect_err("first remote unseal is unavailable"),
    );
    assert_eq!(provider.calls(), 1);
    let plaintext = unseal().await.expect("same envelope can be retried");
    assert_eq!(provider.calls(), 2);
    assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
}
