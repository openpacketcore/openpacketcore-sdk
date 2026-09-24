//! White-box ownership/compatibility controls. The in-memory fixture is not
//! native storage, production transport or whole-operation allocation proof.

use super::*;
use crate::audit_authority::{AuditAuthorityError, AuditPrivacyKey, PreparedAuditedMutation};
use crate::consensus::audit_mutation::AuditedConfigEffect;
use opc_crypto::{ConfigCapacityProfile, ConfigPreparationPool};

fn event() -> crate::ManagementAuditEventRecord {
    crate::ManagementAuditEventRecord::try_new(
        [0x61; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-preparation"),
    )
    .expect("synthetic audit event")
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x62; 32]).expect("synthetic privacy key")
}

#[tokio::test]
async fn config_capacity_957_prepared_aliases_preserve_exact_legacy_bytes_without_pinning_commands()
{
    let (store, _scratch) = singleton_store().await;
    let mut prepared = store
        .prepare_audited_commit(
            &privacy(),
            &event(),
            sized_attested_commit(65_536),
            Duration::from_secs(60),
        )
        .expect("prepared legacy append");
    let pool = ConfigPreparationPool::bounded_v1();
    let _others: Vec<_> = (0..7)
        .map(|_| pool.try_reserve().expect("other owner"))
        .collect();
    prepared.attach_preparation(PreparationOwnership::new(
        pool.try_reserve().expect("eighth"),
        None,
    ));
    let aliases = vec![prepared.clone(); 16];
    assert!(
        aliases
            .iter()
            .all(|alias| std::ptr::eq(alias.handle(), prepared.handle())),
        "clone shares payload"
    );
    let original_blob = match &prepared.command().effect {
        AuditedConfigEffect::Append { commit, .. } => commit.record.encrypted_blob.as_slice(),
        _ => panic!("append fixture"),
    };
    for alias in &aliases {
        let AuditedConfigEffect::Append { commit, .. } = &alias.command().effect else {
            panic!("append alias")
        };
        assert!(
            std::ptr::eq(original_blob, commit.record.encrypted_blob.as_slice()),
            "ciphertext is shared"
        );
    }

    #[derive(Serialize)]
    #[serde(rename = "PreparedAuditedMutation")]
    struct LegacyPrepared<'a> {
        handle: &'a crate::audit_authority::AuditOperationHandle,
        effect: &'a AuditedConfigEffect,
    }
    let legacy = LegacyPrepared {
        handle: prepared.handle(),
        effect: &prepared.command().effect,
    };
    let json = serde_json::to_vec(&legacy).expect("legacy JSON oracle");
    let wire = encode_bounded(&legacy).expect("legacy postcard oracle");
    assert!(
        prepared.encode().expect("SDK encoding") == json,
        "exact legacy JSON"
    );
    assert!(
        encode_bounded(&prepared).expect("prepared wire") == wire,
        "exact legacy postcard"
    );
    assert!(
        encode_bounded(prepared.command()).expect("internal wire") == wire,
        "exact internal postcard"
    );
    let decoded = PreparedAuditedMutation::decode(&json).expect("generic decode");
    assert_eq!(decoded, prepared, "equality excludes local ownership");
    assert!(
        matches!(
            decoded.begin_submission(&pool, ConfigCapacityProfile::BoundedV1),
            Err(AuditAuthorityError::InvalidInput)
        ),
        "generic decode grants no reservation"
    );
    let retained_command = prepared.command().clone();
    drop(prepared);
    assert!(
        pool.try_reserve().is_err(),
        "aliases retain the one preparation"
    );
    drop(aliases);
    let _released = pool
        .try_reserve()
        .expect("deterministic retained payload must not pin preparation");
    assert!(
        encode_bounded(&retained_command).expect("payload still alive") == wire,
        "retained payload bytes unchanged"
    );
    store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn config_capacity_957_alias_guards_reject_foreign_and_overlapping_work() {
    let (store, _scratch) = singleton_store().await;
    let mut prepared = store
        .prepare_audited_confirmation(
            &privacy(),
            &event(),
            opc_types::TxId::new(),
            opc_types::ConfigVersion::new(1),
            Duration::from_secs(60),
        )
        .expect("prepared confirmation");
    let pool = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    let ownership = PreparationOwnership::new(pool.try_reserve().expect("owner"), None);
    prepared.attach_preparation(Arc::clone(&ownership));
    let alias = prepared.clone();
    assert!(matches!(
        alias.begin_submission(&foreign, ConfigCapacityProfile::BoundedV1),
        Err(AuditAuthorityError::InvalidInput)
    ));
    let active = prepared
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .expect("first submit")
        .expect("owned guard");
    let supervisor = Arc::clone(&active);
    assert!(matches!(
        alias.begin_submission(&pool, ConfigCapacityProfile::BoundedV1),
        Err(AuditAuthorityError::Unavailable)
    ));
    drop(active);
    assert!(
        matches!(
            alias.begin_submission(&pool, ConfigCapacityProfile::BoundedV1),
            Err(AuditAuthorityError::Unavailable)
        ),
        "accepted-work owner outlives caller"
    );
    // Read-only handle recovery remains possible while mutation is active.
    assert_eq!(alias.handle(), prepared.handle());
    let encoding = ownership.try_encode().expect("first encoder");
    assert!(
        matches!(alias.encode(), Err(AuditAuthorityError::Unavailable)),
        "no second SDK output allocation"
    );
    drop(encoding);
    assert!(
        alias.encode().is_ok(),
        "encode has independent ownership from submission"
    );
    drop(supervisor);
    let _next = alias
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .expect("completed guard released");
    store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn config_capacity_957_store_recovery_decode_authenticates_original_effect_and_framing() {
    let (store, _scratch) = singleton_store().await;
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &event(),
            sized_attested_commit(32),
            Duration::from_secs(60),
        )
        .expect("prepared append");
    let mut at_limit = prepared.encode().expect("original encoding");
    at_limit.resize(
        crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        b' ',
    );
    let decoded = store
        .decode_prepared_audited_mutation(&at_limit)
        .expect("exact recovery framing limit");
    assert_eq!(decoded, prepared);
    at_limit.push(b' ');
    assert!(matches!(
        store.decode_prepared_audited_mutation(&at_limit),
        Err(AuditAuthorityError::InvalidInput)
    ));
    let changed = PreparedAuditedMutation::new(
        prepared.handle().clone(),
        AuditedConfigEffect::Confirm {
            tx_id: opc_types::TxId::new(),
        },
        None,
    );
    let changed = changed
        .encode()
        .expect("syntactically valid changed effect");
    assert!(
        PreparedAuditedMutation::decode(&changed).is_ok(),
        "structural control"
    );
    assert!(
        matches!(
            store.decode_prepared_audited_mutation(&changed),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "store authenticates original effect"
    );
    store.shutdown().await.expect("shutdown");
}
