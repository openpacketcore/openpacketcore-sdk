//! Direct helper calls after an independent, fully authenticated ledger read.
//! Faults stay in local copies; the real fixture settles before control assertions.

use super::*;
use crate::audit_authority::{AuditAuthorityError, AuditCaller};
use crate::consensus::TargetMutationCommand;

fn retained_mut<'a>(
    ledger: &'a mut LedgerState,
    handle: &AuditOperationHandle,
) -> &'a mut crate::audit_authority::ledger::RetainedTargetIntent {
    ledger
        .entries
        .iter_mut()
        .find_map(|entry| match &mut entry.payload {
            EntryPayload::TargetIntent(retained) if &retained.handle == handle => {
                Some(retained.as_mut())
            }
            _ => None,
        })
        .unwrap()
}

fn canonical(command: &TargetMutationCommand) -> String {
    // Independent ordinary serializer, not the borrowed verification helper.
    serde_json::to_string(command).unwrap()
}

fn running_result(command: &TargetMutationCommand) -> NetconfTargetResult {
    let record = &command.bounded_running().unwrap().commit().record;
    NetconfTargetResult::new(
        identity(),
        command.effect.profile_incarnation,
        [0xd1; 32],
        NetconfAppliedOutcome::RunningReplaced {
            tx_id: record.tx_id,
            running_version: record.version.get(),
            plaintext_digest: record.plaintext_digest.as_slice().try_into().unwrap(),
        },
    )
    .unwrap()
}

fn other_identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0xd2; 32]),
        identity().configuration_id(),
        identity().configuration_epoch(),
    )
}

fn rejected_matches(
    ledger: &LedgerState,
    key: &AuditKey,
    command: &TargetMutationCommand,
    caller: AuditCaller,
) {
    let before = ledger.clone();
    assert!(ledger.matches_target(key, command, caller).is_err());
    assert!(ledger == &before, "comparison changed the complete ledger");
}

fn rejected_resolution(
    mut ledger: LedgerState,
    key: &AuditKey,
    handle: &AuditOperationHandle,
    state: AuditOperationState,
    hint: &TargetMutationCommand,
) {
    let before = ledger.clone();
    assert!(ledger
        .resolve_with_original(key, handle, state, Some(hint))
        .is_err());
    assert!(
        ledger == before,
        "rejection changed state, entries or anchors"
    );
}

// These scopes observe actual decode/verification work at a direct call. They
// do not claim that the full Apply reducer entered or completed.
fn direct_work<T>(handle: &AuditOperationHandle, call: impl FnOnce() -> T) -> (T, Work) {
    let watch = ApplyWatch::start(handle);
    let scope = ApplyScope::enter(handle);
    let result = call();
    drop(scope);
    (result, watch.finish())
}

#[test]
fn joint_apply_original_direct_scope_and_outcome_checks() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let command = f.original.command();
    let handle = command.handle();
    let caller = command.effect.caller;
    let ledger = f.ledger();
    let database = snapshot(&f.conn);
    assert!(ledger.matches_target(&key(), command, caller).unwrap());

    // The explicit caller is an input to comparison. Resolution instead binds
    // its operation handle and retained effect to their authenticated caller.
    let other_caller = AuditCaller::project(&privacy(), "other-tenant", "other-principal").unwrap();
    assert_ne!(other_caller, caller);
    rejected_matches(&ledger, &key(), command, other_caller);
    // Even with the original authenticated handle, a changed retained effect
    // cannot acquire a different caller through an exact canonical hint.
    let mut changed_caller = command.clone();
    changed_caller.effect.caller = other_caller;
    let mut caller_ledger = ledger.clone();
    retained_mut(&mut caller_ledger, handle).recovery = canonical(&changed_caller);
    rejected_matches(&caller_ledger, &key(), &changed_caller, caller);
    rejected_resolution(
        caller_ledger,
        &key(),
        handle,
        AuditOperationState::Rejected,
        &changed_caller,
    );
    let wrong_key = AuditKey::new([0xd3; 32]).unwrap();
    rejected_matches(&ledger, &wrong_key, command, caller);
    rejected_resolution(
        ledger.clone(),
        &wrong_key,
        handle,
        AuditOperationState::Rejected,
        command,
    );

    let mut wrong_identity = ledger.clone();
    wrong_identity.identity = other_identity();
    rejected_matches(&wrong_identity, &key(), command, caller);
    rejected_resolution(
        wrong_identity,
        &key(),
        handle,
        AuditOperationState::Rejected,
        command,
    );

    // A valid signed handle for another operation must not locate this Intent.
    let mut body = handle.body.clone();
    body.nonce[0] ^= 1;
    let other_handle = AuditOperationHandle::issue(body, &key()).unwrap();
    other_handle.verify(&key(), identity(), caller).unwrap();
    let mut other_command = command.clone();
    other_command.handle = other_handle.clone();
    rejected_matches(&ledger, &key(), &other_command, caller);
    rejected_resolution(
        ledger.clone(),
        &key(),
        &other_handle,
        AuditOperationState::Rejected,
        &other_command,
    );

    // Comparison must recover the original at the operation's first sequence.
    // Resolution's existing contract uses the retained handle, not this index.
    let mut wrong_first = ledger.clone();
    let absent_sequence = wrong_first.sequence.checked_add(1).unwrap();
    wrong_first
        .operations
        .iter_mut()
        .find(|operation| &operation.handle == handle)
        .unwrap()
        .first_sequence = absent_sequence;
    rejected_matches(&wrong_first, &key(), command, caller);

    let result = running_result(command);
    command.validate_result(result).unwrap();
    let mut wrong_profile = result.profile_incarnation();
    wrong_profile[0] ^= 0x80;
    for invalid in [
        NetconfTargetResult::new(
            other_identity(),
            result.profile_incarnation(),
            result.state_digest(),
            result.outcome(),
        )
        .unwrap(),
        NetconfTargetResult::new(
            identity(),
            wrong_profile,
            result.state_digest(),
            result.outcome(),
        )
        .unwrap(),
        NetconfTargetResult::new(
            identity(),
            result.profile_incarnation(),
            result.state_digest(),
            match result.outcome() {
                NetconfAppliedOutcome::RunningReplaced {
                    tx_id,
                    running_version,
                    mut plaintext_digest,
                } => {
                    plaintext_digest[0] ^= 1;
                    NetconfAppliedOutcome::RunningReplaced {
                        tx_id,
                        running_version,
                        plaintext_digest,
                    }
                }
                _ => unreachable!(),
            },
        )
        .unwrap(),
    ] {
        rejected_resolution(
            ledger.clone(),
            &key(),
            handle,
            AuditOperationState::TargetV1(invalid),
            command,
        );
    }
    rejected_resolution(
        ledger.clone(),
        &key(),
        handle,
        AuditOperationState::Committed { version: 1 },
        command,
    );

    let mut borrowed = ledger.clone();
    borrowed
        .resolve_with_original(
            &key(),
            handle,
            AuditOperationState::TargetV1(result),
            Some(command),
        )
        .unwrap();
    let mut owned = ledger;
    owned
        .resolve_with_original(&key(), handle, AuditOperationState::TargetV1(result), None)
        .unwrap();
    assert!(borrowed == owned, "hint changed the authenticated outcome");
    borrowed.seal_continuity(Some(&f.keys)).unwrap();
    borrowed.validate(&key(), identity()).unwrap();
    borrowed.validate_continuity(Some(&f.keys)).unwrap();
    assert_eq!(
        borrowed
            .recover_target(&key(), handle, caller)
            .unwrap()
            .command(),
        command
    );
    assert_eq!(snapshot(&f.conn), database);
    drop((borrowed, owned, wrong_first, other_command));
    apply_rejection(&f);
    settle(f);
}

#[test]
fn joint_apply_original_direct_retained_bytes_and_fallback() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let command = f.original.command();
    let handle = command.handle();
    let caller = command.effect.caller;
    let ledger = f.ledger();
    let database = snapshot(&f.conn);
    let bytes = canonical(command);
    assert!(bytes.len() > 4096);
    assert_eq!(retained_mut(&mut ledger.clone(), handle).recovery, bytes);

    // Valid JSON with an extra byte must take the real owned decoder and fail
    // canonical checking. A truncated document must also fail both boundaries.
    let mut noncanonical = bytes.clone();
    noncanonical.push(' ');
    let mut truncated = bytes.clone();
    truncated.pop().unwrap();
    for recovery in [noncanonical, truncated] {
        let mut changed = ledger.clone();
        retained_mut(&mut changed, handle).recovery = recovery;
        let before = changed.clone();
        let (result, work) =
            direct_work(handle, || changed.matches_target(&key(), command, caller));
        assert!(result.is_err());
        assert!(changed == before);
        assert_eq!(work.borrowed, 0);
        let (result, resolution_work) = direct_work(handle, || {
            changed.resolve_with_original(
                &key(),
                handle,
                AuditOperationState::Rejected,
                Some(command),
            )
        });
        assert!(result.is_err());
        assert!(changed == before);
        assert_eq!(resolution_work.borrowed, 0);
        if retained_mut(&mut changed, handle).recovery.ends_with(' ') {
            assert_eq!((work.owned, work.verified), (1, 0));
            assert_eq!((resolution_work.owned, resolution_work.verified), (1, 0));
        }
    }

    // A differing hint is not authority and must not invalidate the stored
    // original. Authenticate that original through the owned fallback.
    let mut misleading = command.clone();
    misleading.effect.profile_incarnation[0] ^= 0x80;
    let (matches, work) = direct_work(handle, || {
        ledger.matches_target(&key(), &misleading, caller)
    });
    assert!(!matches.unwrap());
    assert_eq!((work.owned, work.verified, work.borrowed), (1, 1, 0));
    let result = running_result(command);
    let mut resolved = ledger.clone();
    let (resolution, work) = direct_work(handle, || {
        resolved.resolve_with_original(
            &key(),
            handle,
            AuditOperationState::TargetV1(result),
            Some(&misleading),
        )
    });
    resolution.unwrap();
    assert_eq!((work.owned, work.verified, work.borrowed), (1, 1, 0));
    let mut owned = ledger.clone();
    owned
        .resolve(&key(), handle, AuditOperationState::TargetV1(result))
        .unwrap();
    assert!(resolved == owned);
    rejected_resolution(
        ledger,
        &key(),
        handle,
        AuditOperationState::TargetV1(running_result(&misleading)),
        &misleading,
    );
    assert_eq!(snapshot(&f.conn), database);
    drop((resolved, owned, misleading));
    apply_rejection(&f);
    settle(f);
}

fn canonical_substitution() -> (Fixture, LedgerState, TargetMutationCommand) {
    let f = Fixture::new(4096);
    f.checkpoint();
    // This independently authenticates the real row, chain and original first.
    // The corruption below occurs only in the returned local ledger copy.
    let mut ledger = f.ledger();
    let original = f.original.command();
    assert!(ledger
        .matches_target(&key(), original, original.effect.caller)
        .unwrap());
    assert_eq!(
        ledger
            .recover_target(&key(), original.handle(), original.effect.caller)
            .unwrap()
            .command(),
        original
    );
    let mut substituted = original.clone();
    substituted.effect.device_incarnation[0] ^= 0x80;
    assert_ne!(
        original_mac(
            &key(),
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &substituted.effect,
        ),
        substituted.handle().body.mutation.unwrap(),
        "the canonical substitute deliberately lacks a valid effect authenticator"
    );
    let bytes = canonical(&substituted);
    assert!(bytes.len() > 4096);
    let mut comparison_bytes = Vec::new();
    crate::consensus::config_capacity_json::to_writer(&mut comparison_bytes, &substituted).unwrap();
    assert_eq!(comparison_bytes.as_slice(), bytes.as_bytes());
    retained_mut(&mut ledger, original.handle()).recovery = bytes.clone();
    assert_eq!(
        retained_mut(&mut ledger, substituted.handle()).recovery,
        canonical(&substituted)
    );
    (f, ledger, substituted)
}

#[test]
fn joint_apply_original_matches_target_reauthenticates_canonical_substitution() {
    let (f, ledger, substituted) = canonical_substitution();
    let before = ledger.clone();
    let database = snapshot(&f.conn);
    let result: Result<bool, AuditAuthorityError> =
        ledger.matches_target(&key(), &substituted, substituted.effect.caller);
    let unchanged = ledger == before;
    assert_eq!(snapshot(&f.conn), database);
    drop((ledger, before, substituted));
    apply_rejection(&f);
    settle(f);
    eprintln!("APPLY_ORIGINAL_MATCHES_SUBSTITUTION_RECOVERY_CHECKPOINT_CLEANUP_COMPLETED unchanged={unchanged}");
    assert!(
        result.is_err(),
        "APPLY_ORIGINAL_MATCHES_CANONICAL_SUBSTITUTION_REQUIRES_FRESH_AUTH"
    );
    assert!(unchanged, "comparison changed state, entries or anchors");
}

#[test]
fn joint_apply_original_resolve_reauthenticates_canonical_substitution() {
    let (f, mut ledger, substituted) = canonical_substitution();
    let before = ledger.clone();
    let database = snapshot(&f.conn);
    let result = ledger.resolve_with_original(
        &key(),
        substituted.handle(),
        AuditOperationState::Rejected,
        Some(&substituted),
    );
    let unchanged = ledger == before;
    assert_eq!(snapshot(&f.conn), database);
    drop((ledger, before, substituted));
    apply_rejection(&f);
    settle(f);
    eprintln!("APPLY_ORIGINAL_RESOLVE_SUBSTITUTION_RECOVERY_CHECKPOINT_CLEANUP_COMPLETED unchanged={unchanged}");
    assert!(
        result.is_err(),
        "APPLY_ORIGINAL_RESOLVE_CANONICAL_SUBSTITUTION_REQUIRES_FRESH_AUTH"
    );
    assert!(unchanged, "resolution changed state, entries or anchors");
}
