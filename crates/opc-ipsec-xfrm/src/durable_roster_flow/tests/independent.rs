//! Independent fixture schedules through the existing private fault harness.
//! Public inspection authenticates the real store. The backend is scripted;
//! process-crash/Linux evidence is qualified separately.
use super::*;

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/roster-lifecycle.tsv"
));

fn numbers(text: &str) -> Vec<usize> {
    if text == "-" {
        Vec::new()
    } else {
        text.split(',').map(|v| v.parse().unwrap()).collect()
    }
}

fn phases(members: &XfrmObjectRosterMemberDispositions) -> Vec<&'static str> {
    members.iter().map(|member| member.phase()).collect()
}

async fn presence(backend: &ScriptedBackend, roster: &XfrmObjectRosterRequest) -> Vec<usize> {
    let mut observed = Vec::new();
    for member in roster.members() {
        observed.push(usize::from(backend.is_present(member.request()).await));
    }
    observed
}

fn assert_redacted(text: &str) {
    for forbidden in [
        "198.51.100",
        "10.67.0",
        "163368",
        "0x6160",
        "KeyMaterial",
        "Tunnel",
    ] {
        assert!(!text.contains(forbidden), "value-bearing roster diagnostic");
    }
}

#[tokio::test]
async fn independent_roster_lifecycle_schedules_match_order_truth_and_recovery() {
    let mut names = std::collections::BTreeSet::new();
    for row in REFERENCE.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 17);
        let name = fields[0];
        assert!(names.insert(name), "unique independent schedule");
        let kinds: Vec<_> = fields[1]
            .bytes()
            .map(|kind| match kind {
                b's' => Kind::Sa,
                b'p' => Kind::Policy,
                _ => panic!("invalid reference member kind"),
            })
            .collect();
        assert!((1..=8).contains(&kinds.len()));
        let trigger = fields[2];
        let ordinal = fields[3].parse::<usize>().ok();
        assert_eq!(
            fields[4],
            if trigger == "issuing-after" { "1" } else { "0" }
        );
        let root = TestRoot::new();
        let roster = roster_of(&kinds);
        let backend = ScriptedBackend::for_roster(&roster);
        let store = open_store(&root);
        let group_id = group(0x79);
        let generation = generation(1);
        match trigger {
            "sweep-failure" => backend.fail_query(ordinal.unwrap(), 0, XfrmError::Unavailable),
            "install-failure" => backend.fail_install(ordinal.unwrap(), XfrmError::Unavailable),
            "foreign-conflict" => {
                backend
                    .plant(roster.member(ordinal.unwrap()).unwrap().request())
                    .await;
            }
            _ => {}
        }
        let prepared = prepare_object_roster(&store, group_id, generation, &roster).unwrap();
        let (handle, outcome) = match trigger {
            "recover-prepared" => (prepared.clone(), "not-run"),
            "issuing-before" | "issuing-after" => (
                cut_durable_object_roster_at_issuing_member(
                    &store,
                    &prepared,
                    group_id,
                    generation,
                    &roster,
                    &backend,
                    ordinal.unwrap(),
                    trigger == "issuing-after",
                )
                .await
                .unwrap(),
                "cut",
            ),
            _ => {
                let result = issue_durable_object_roster(
                    &store, &prepared, group_id, generation, &roster, &backend,
                )
                .await;
                if trigger == "sweep-failure" {
                    let error = result.unwrap_err();
                    assert!(error.is_proved_clean(), "{name}");
                    assert_redacted(&format!("{error:?} {error}"));
                    (prepared.clone(), error.as_str())
                } else {
                    let result = result.unwrap();
                    assert_redacted(&format!("{result:?}"));
                    if trigger == "install-failure" {
                        assert_eq!(result.failed_member(), ordinal, "{name}");
                        assert!(matches!(result.source(), Some(XfrmError::Unavailable)));
                    }
                    (result.handle().clone(), result.as_str())
                }
            }
        };
        assert_eq!(outcome, fields[6], "{name}");
        assert_eq!(
            store.inspect(&handle).unwrap().as_str(),
            fields[5],
            "{name}"
        );
        let members = store
            .inspect_dispositions(&handle, group_id, generation, &roster)
            .unwrap();
        assert_eq!(
            phases(&members),
            fields[10].split(',').collect::<Vec<_>>(),
            "{name}"
        );
        assert_eq!(
            backend.ordinals(OpKind::Install),
            numbers(fields[7]),
            "{name}"
        );
        assert_eq!(
            backend.ordinals(OpKind::Remove),
            numbers(fields[8]),
            "{name}"
        );
        assert_eq!(
            presence(&backend, &roster).await,
            numbers(fields[9]),
            "{name}"
        );
        if trigger == "foreign-conflict" {
            assert_eq!(
                backend.ordinals(OpKind::Query),
                (0..kinds.len()).collect::<Vec<_>>()
            );
            for member in members.iter() {
                assert_eq!(
                    member.is_conflicting(),
                    Some(member.ordinal()) == ordinal,
                    "{name}"
                );
                assert_eq!(member.adjacent_proof(), None, "{name}");
            }
        }
        if handle != prepared {
            assert!(matches!(
                store.inspect(&prepared),
                Err(XfrmObjectRosterDurableError::Stale)
            ));
        }
        assert_redacted(&format!("{handle:?} {handle} {members:?}"));
        // Reopen the authenticated store while retaining the scripted backend.
        // This does not substitute for a real process crash or Linux packet run.
        drop(store);
        backend.clear_faults();
        backend.clear_log();
        let store = open_store(&root);
        let (finished, members) = match fields[11] {
            "finalize" => {
                let phase =
                    finalize_durable_object_roster(&store, group_id, generation, &roster).unwrap();
                let result =
                    recover_durable_object_roster(&store, group_id, generation, &roster, &backend)
                        .await
                        .unwrap();
                (phase.as_str(), *result.members())
            }
            "adopt" => {
                let result =
                    adopt_durable_object_roster(&store, group_id, generation, &roster, &backend)
                        .await
                        .unwrap();
                (result.as_str(), *result.members())
            }
            "recover" => {
                let result =
                    recover_durable_object_roster(&store, group_id, generation, &roster, &backend)
                        .await
                        .unwrap();
                (result.as_str(), *result.members())
            }
            _ => panic!("unknown reference completion operation"),
        };
        assert_eq!(finished, fields[12], "{name}");
        assert_eq!(
            backend.ordinals(OpKind::Remove),
            numbers(fields[13]),
            "{name}"
        );
        assert!(backend.ordinals(OpKind::Install).is_empty(), "{name}");
        assert_eq!(
            presence(&backend, &roster).await,
            numbers(fields[14]),
            "{name}"
        );
        assert_eq!(
            phases(&members),
            fields[15].split(',').collect::<Vec<_>>(),
            "{name}"
        );
        assert!(store.inspect(&handle).is_err(), "superseded handle: {name}");
        let effects = backend.effects();
        let repeated =
            recover_durable_object_roster(&store, group_id, generation, &roster, &backend)
                .await
                .unwrap();
        assert_eq!(repeated.as_str(), fields[16], "{name}");
        assert_eq!(phases(repeated.members()), phases(&members), "{name}");
        assert_eq!(backend.effects(), effects, "idempotent recovery: {name}");
        assert_redacted(&format!("{repeated:?}"));
    }
    assert_eq!(names.len(), 636);
}

#[tokio::test]
async fn independent_roster_inspection_rejects_tampered_stale_and_substituted_handles() {
    let root = TestRoot::new();
    let roster = roster_of(&CHILD_SA_ROSTER);
    let backend = ScriptedBackend::for_roster(&roster);
    let store = open_store(&root);
    let group_id = group(0x79);
    let current = generation(1);
    let result = run_roster(&store, group_id, current, &roster, &backend)
        .await
        .unwrap();
    let handle = result.handle();
    assert_eq!(
        store.inspect(handle).unwrap(),
        XfrmObjectRosterDurablePhase::Applied
    );
    // The public fixed-size wrapper alone never authenticates correlation.
    // Mutate every byte, including the entire tag, without printing any bytes.
    let original = handle.to_bytes();
    for offset in 0..original.len() {
        let mut changed = original;
        changed[offset] ^= 1;
        let forged = XfrmObjectRosterRecoveryHandle::from_bytes(changed);
        assert!(
            store.inspect(&forged).is_err(),
            "tampered handle at ordinal {offset}"
        );
    }
    assert_eq!(
        store.inspect(handle).unwrap(),
        XfrmObjectRosterDurablePhase::Applied
    );
    let reversed =
        XfrmObjectRosterRequest::new(roster.members().iter().rev().cloned().collect()).unwrap();
    let substituted = roster_of(&[Kind::Sa; 5]);
    for (candidate_group, candidate_generation, candidate_roster) in [
        (group(0x7a), current, &roster),
        (group_id, generation(2), &roster),
        (group_id, current, &reversed),
        (group_id, current, &substituted),
    ] {
        let error = store
            .inspect_dispositions(
                handle,
                candidate_group,
                candidate_generation,
                candidate_roster,
            )
            .unwrap_err();
        assert_eq!(error, XfrmObjectRosterDurableError::WrongBinding);
        assert_redacted(&format!("{error:?} {error}"));
    }
    assert_eq!(presence(&backend, &roster).await, vec![1; 5]);
    assert!(backend.ordinals(OpKind::Remove).is_empty());
    finalize_durable_object_roster(&store, group_id, current, &roster).unwrap();
    assert_eq!(
        store.inspect(handle).unwrap_err(),
        XfrmObjectRosterDurableError::Stale
    );
    assert_eq!(
        store
            .inspect_dispositions(handle, group_id, current, &roster)
            .unwrap_err(),
        XfrmObjectRosterDurableError::Stale
    );
    assert_eq!(presence(&backend, &roster).await, vec![1; 5]);
    assert!(backend.ordinals(OpKind::Remove).is_empty());
}
