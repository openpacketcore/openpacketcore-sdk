use super::*;
use crate::child_sa::*;
use crate::durable_relocation::*;
use crate::*;
use opc_proto_ikev2::nwu::mobike::Path;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let id = XfrmSaRelocationOperationId::generate().unwrap();
        let suffix = id
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("opc-childsa-relocation-{suffix}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pair(child: u64, incarnation: u64, selected: bool) -> ChildSaInstalledPairRequest {
    let peer = IpAddress::Ipv4([192, 0, 2, 10]);
    let local = IpAddress::Ipv4([192, 0, 2, 20]);
    let inbound_sa = SaParameters {
        selector: XfrmSelector::new(IpAddress::Ipv4([0; 4]), IpAddress::Ipv4([0; 4]), 0),
        id: XfrmId {
            destination: local,
            spi: 0x1000 + child as u32 * 16 + incarnation as u32 * 2,
            protocol: 50,
        },
        source_address: peer,
        request_id: XfrmRequestId::new(child as u32),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x53; 32]),
        )),
        crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0x74; 16]))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: Some(UdpEncap::esp_in_udp(4500, 4500)),
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    };
    let mut outbound_sa = inbound_sa.clone();
    outbound_sa.id.destination = peer;
    outbound_sa.id.spi += 1;
    outbound_sa.source_address = local;
    outbound_sa.mark = Some(XfrmLookupMark::full(child as u32));
    let policy = |sa: &SaParameters, direction| PolicyParameters {
        selector: sa.selector.clone(),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: sa.id,
            source_address: sa.source_address,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
        mark: sa.mark,
        if_id: sa.if_id,
    };
    let mut inbound_policy = policy(&inbound_sa, XfrmDirection::In);
    // Distinct child policies cannot share a selector/mark lookup identity.
    // This shared request-ID policy admits the rekey overlap for child one;
    // separate lookup marks keep the other synthetic inbound child policies exact.
    let mut inbound_sa = inbound_sa;
    inbound_sa.mark = Some(XfrmLookupMark::full(child as u32));
    inbound_policy.mark = inbound_sa.mark;
    inbound_policy.templates[0].id.spi = 0;
    let pair = ChildSaPair::new(
        ChildSaId::new(child).unwrap(),
        ChildSaIncarnation::new(incarnation).unwrap(),
        ChildSaTrafficIdentity::new(inbound_sa.id, inbound_sa.mark, inbound_sa.if_id).unwrap(),
        ChildSaTrafficIdentity::new(outbound_sa.id, outbound_sa.mark, outbound_sa.if_id).unwrap(),
        if selected {
            ChildSaOutboundUse::Selected
        } else {
            ChildSaOutboundUse::ReceiveOnly
        },
    );
    ChildSaInstalledPairRequest {
        pair,
        inbound_sa,
        inbound_policy,
        outbound_policy: selected.then(|| policy(&outbound_sa, XfrmDirection::Out)),
        outbound_sa,
    }
}

pub(crate) fn intent(udp: bool) -> ChildSaRelocationIntent {
    let pairs = vec![
        pair(1, 1, false),
        pair(1, 2, true),
        pair(2, 1, true),
        pair(3, 1, true),
    ];
    let plan = ChildSaSelectionPlan::new(
        pairs.iter().map(|pair| pair.pair.clone()).collect(),
        [(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (31, 3)]
            .into_iter()
            .map(|(flow, child)| {
                ChildSaClassBinding::new(
                    ChildSaClass::new(flow).unwrap(),
                    ChildSaId::new(child).unwrap(),
                )
            })
            .collect(),
        ChildSaId::new(3).unwrap(),
        ChildSaSelectionLimits {
            max_pairs: 8,
            max_classes: 256,
        },
    )
    .unwrap();
    ChildSaRelocationIntent {
        current: ChildSaInstalledRosterRequest { plan, pairs },
        path: Path::new(
            "198.51.100.10:4501".parse().unwrap(),
            "198.51.100.20:4502".parse().unwrap(),
        )
        .unwrap(),
        esp_udp: udp,
    }
}

#[derive(Clone)]
struct State {
    sas: Vec<SaParameters>,
    policies: Vec<PolicyParameters>,
    calls: usize,
    writes: usize,
    fail: Option<(usize, bool)>,
}
struct World(Mutex<State>);
impl World {
    fn new(program: &Program) -> Self {
        Self(Mutex::new(State {
            sas: program.sas.iter().map(|sa| sa.old.clone()).collect(),
            policies: program
                .policies
                .iter()
                .map(|policy| policy.old.clone())
                .collect(),
            calls: 0,
            writes: 0,
            fail: None,
        }))
    }
    fn event<T>(
        &self,
        write: bool,
        operation: impl FnOnce(&mut State) -> Result<T, XfrmError>,
    ) -> Result<T, XfrmError> {
        let mut state = self.0.lock().unwrap();
        let ordinal = state.calls;
        state.calls += 1;
        if state.fail == Some((ordinal, false)) {
            return Err(XfrmError::Unavailable);
        }
        let result = operation(&mut state)?;
        if write {
            state.writes += 1;
        }
        if state.fail == Some((ordinal, true)) {
            return Err(XfrmError::StateIndeterminate {
                operation: "test_roster_cut",
            });
        }
        Ok(result)
    }
}
#[async_trait]
impl RelocationIo for World {
    async fn sa_is_new(&self, resource: &SaMove) -> Result<bool, XfrmError> {
        self.event(false, |state| {
            let old = state.sas.iter().filter(|sa| *sa == &resource.old).count();
            let new = state.sas.iter().filter(|sa| *sa == &resource.new).count();
            match (old, new) {
                (1, 0) => Ok(false),
                (0, 1) => Ok(true),
                _ => Err(mismatch()),
            }
        })
    }
    async fn policy(&self, resource: &PolicyMove) -> Result<PolicyParameters, XfrmError> {
        self.event(false, |state| {
            state
                .policies
                .iter()
                .find(|policy| policy_query(policy) == policy_query(&resource.old))
                .cloned()
                .ok_or_else(mismatch)
        })
    }
    async fn move_sa(&self, resource: &SaMove) -> Result<(), XfrmError> {
        self.event(true, |state| {
            if resource.request.direction == SaRelocationDirection::OutboundBlockPolicyInstalled {
                assert!(state
                    .policies
                    .iter()
                    .any(|policy| policy.direction == XfrmDirection::Out
                        && policy.action == XfrmAction::Block
                        && policy.mark == resource.old.mark
                        && policy.selector == resource.old.selector));
            }
            let sa = state
                .sas
                .iter_mut()
                .find(|sa| **sa == resource.old)
                .ok_or_else(mismatch)?;
            *sa = resource.new.clone();
            Ok(())
        })
    }
    async fn put_policy(&self, policy: &PolicyParameters) -> Result<(), XfrmError> {
        self.event(true, |state| {
            let current = state
                .policies
                .iter_mut()
                .find(|current| policy_query(current) == policy_query(policy))
                .ok_or_else(mismatch)?;
            *current = policy.clone();
            Ok(())
        })
    }
}

#[tokio::test]
async fn every_native_and_natt_mutation_and_readback_cut_resumes_only_complete_program() {
    for udp in [false, true] {
        let intent = intent(udp);
        let program = intent.program().unwrap();
        assert_eq!(program.sas.len(), 8);
        assert_eq!(program.policies.len(), 6);
        assert_eq!(program.steps.len(), 17);
        let reference = World::new(&program);
        program.finish(&reference, || Ok(())).await.unwrap();
        let calls = reference.0.lock().unwrap().calls;
        for ordinal in 0..calls {
            for after in [false, true] {
                let world = World::new(&program);
                world.0.lock().unwrap().fail = Some((ordinal, after));
                assert!(
                    program.finish(&world, || Ok(())).await.is_err(),
                    "cut {ordinal}, after={after}, udp={udp}"
                );
                // Throw away runtime progress. Recovery derives its next step
                // only from physical state and the original complete intent.
                let mut state = world.0.lock().unwrap().clone();
                state.fail = None;
                state.calls = 0;
                let restarted = World(Mutex::new(state));
                intent
                    .program()
                    .unwrap()
                    .finish(&restarted, || Ok(()))
                    .await
                    .unwrap();
                assert_eq!(
                    program.prefix(&restarted).await.unwrap(),
                    program.steps.len()
                );
                assert_eq!(
                    restarted.0.lock().unwrap().sas,
                    reference.0.lock().unwrap().sas
                );
                assert_eq!(
                    restarted.0.lock().unwrap().policies,
                    reference.0.lock().unwrap().policies
                );
            }
        }
        for (old, new) in intent.current.pairs.iter().zip(&program.updated.pairs) {
            assert_eq!(old.inbound_sa.selector, new.inbound_sa.selector);
            assert_eq!(old.outbound_sa.selector, new.outbound_sa.selector);
            assert_eq!(old.inbound_sa.auth, new.inbound_sa.auth);
            assert_eq!(old.outbound_sa.crypt, new.outbound_sa.crypt);
            assert_eq!(old.inbound_sa.replay_window, new.inbound_sa.replay_window);
            assert_eq!(old.pair.incarnation(), new.pair.incarnation());
        }
        assert_eq!(
            intent.current.plan.classes(),
            program.updated.plan.classes()
        );
        assert_eq!(
            intent.current.plan.default_child(),
            program.updated.plan.default_child()
        );
    }
}

#[tokio::test]
async fn every_encapsulation_transition_preserves_the_complete_inner_contract() {
    for old_udp in [false, true] {
        for new_udp in [false, true] {
            let mut intent = intent(new_udp);
            if !old_udp {
                for pair in &mut intent.current.pairs {
                    pair.inbound_sa.encap = None;
                    pair.outbound_sa.encap = None;
                }
            }
            let program = intent.program().unwrap();
            let world = World::new(&program);
            program.finish(&world, || Ok(())).await.unwrap();
            for resource in &program.sas {
                assert_eq!(resource.old.selector, resource.new.selector);
                assert_eq!(resource.new.encap.is_some(), new_udp);
                assert_eq!(resource.old.encap.is_some(), old_udp);
                match (old_udp, new_udp, resource.request.encap) {
                    (false, false, SaRelocationEncap::Preserve)
                    | (true, false, SaRelocationEncap::Remove)
                    | (_, true, SaRelocationEncap::Set(_)) => {}
                    _ => panic!("incorrect encapsulation transition"),
                }
            }
        }
    }
}

#[tokio::test]
async fn eight_pair_boundary_and_unsupported_adapters_are_explicit() {
    for backend in [
        &MockXfrmBackend::new() as &dyn XfrmBackend,
        &LinuxXfrmBackend::new() as &dyn XfrmBackend,
    ] {
        assert_eq!(
            backend.child_sa_relocation_capability().await.unwrap(),
            XfrmCapability::Missing
        );
    }
    for count in [8, 9] {
        let mut request = intent(true);
        request.current.pairs = (1..=count).map(|child| pair(child, 1, true)).collect();
        request.current.plan = ChildSaSelectionPlan::new(
            request
                .current
                .pairs
                .iter()
                .map(|pair| pair.pair.clone())
                .collect(),
            vec![],
            ChildSaId::new(1).unwrap(),
            ChildSaSelectionLimits {
                max_pairs: 32,
                max_classes: 256,
            },
        )
        .unwrap();
        if count == 8 {
            let program = request.program().unwrap();
            assert_eq!(program.sas.len(), 16);
            let world = World::new(&program);
            program.finish(&world, || Ok(())).await.unwrap();
            assert_eq!(program.prefix(&world).await.unwrap(), program.steps.len());
        } else {
            assert!(matches!(
                request.program(),
                Err(XfrmError::UnsupportedFeature {
                    feature: "child_sa_roster_relocation_profile"
                })
            ));
        }
    }
}

#[tokio::test]
async fn foreign_member_missing_member_and_nonprefix_mixture_never_write() {
    let program = intent(true).program().unwrap();
    for ordinal in 0..program.sas.len() {
        for foreign in [false, true] {
            let world = World::new(&program);
            {
                let mut state = world.0.lock().unwrap();
                if foreign {
                    state.sas[ordinal].auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x99; 32]);
                } else {
                    state.sas.remove(ordinal);
                }
            }
            assert!(program.finish(&world, || Ok(())).await.is_err());
            assert_eq!(world.0.lock().unwrap().writes, 0);
        }
    }
    // All combinations of old/new SAs with the required blocks in place.
    // Only an ordered prefix of new SAs is a reachable program state.
    for mask in 0u16..256 {
        let world = World::new(&program);
        {
            let mut state = world.0.lock().unwrap();
            for (index, resource) in program.sas.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    state.sas[index] = resource.new.clone();
                }
            }
            for (index, resource) in program.policies.iter().enumerate() {
                if let Some(block) = &resource.block {
                    state.policies[index] = block.clone();
                }
            }
        }
        let reachable = (0..=8).any(|count| mask == (1u16 << count) - 1);
        assert_eq!(
            program.prefix(&world).await.is_ok(),
            reachable,
            "SA mask {mask}"
        );
        if !reachable {
            assert!(program.finish(&world, || Ok(())).await.is_err());
            assert_eq!(world.0.lock().unwrap().writes, 0);
        }
    }
}

#[tokio::test]
async fn revoked_live_authority_stops_before_next_effect_or_completion() {
    let program = intent(true).program().unwrap();
    for cut in 0..=program.steps.len() {
        let world = World::new(&program);
        let revoked = AtomicBool::new(false);
        assert!(program
            .finish(&world, || {
                if world.0.lock().unwrap().writes >= cut {
                    revoked.store(true, Ordering::Release);
                }
                if revoked.load(Ordering::Acquire) {
                    Err(ChildSaRelocationError::Authentication)
                } else {
                    Ok(())
                }
            })
            .await
            .is_err());
        assert_eq!(world.0.lock().unwrap().writes, cut);
        // A subsequent recovery has durable target authority, but this helper
        // returns no installed or IKE publication, even when the move is complete.
        program.finish(&world, || Ok(())).await.unwrap();
    }
}

#[test]
fn complete_fingerprints_bind_members_classes_keys_targets_and_record_family() {
    let directory = TestDirectory::new();
    let store = XfrmSaRelocationRecoveryStore::open_bound(
        &directory.0,
        XfrmSaRelocationRecoveryProofKey::new([0x63; 32]).unwrap(),
        [0xa6; 40],
    )
    .unwrap();
    let intent = intent(true);
    let program = intent.program().unwrap();
    let fingerprints = store
        .fingerprints_for_child_roster(&intent, &program.updated)
        .unwrap();
    let id = XfrmSaRelocationOperationId::from_bytes([0x48; 16]).unwrap();
    let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
    let handle = store.prepare(id, generation, fingerprints).unwrap();
    assert!(store.has_unresolved_writer_authority().unwrap());
    for byte in 0..XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES {
        for bit in [1, 128] {
            let mut encoded = handle.to_bytes();
            encoded[byte] ^= bit;
            assert!(
                store
                    .restore_handle(
                        &XfrmSaRelocationRecoveryHandle::from_bytes(encoded),
                        fingerprints
                    )
                    .is_err(),
                "authenticated handle byte {byte}"
            );
        }
    }
    assert_eq!(
        store.inspect(&handle).unwrap(),
        XfrmSaRelocationDurablePhase::Prepared
    );
    assert!(store
        .restore_handle(
            &handle,
            store
                .fingerprints_for_request(&program.sas[0].request)
                .unwrap()
        )
        .is_err());
    for ordinal in 0..intent.current.pairs.len() {
        for inbound in [false, true] {
            let mut changed = intent.clone();
            let pair = &mut changed.current.pairs[ordinal];
            let sa = if inbound {
                &mut pair.inbound_sa
            } else {
                &mut pair.outbound_sa
            };
            sa.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x36; 32]);
            let changed_program = changed.program().unwrap();
            assert!(store
                .restore_handle(
                    &handle,
                    store
                        .fingerprints_for_child_roster(&changed, &changed_program.updated)
                        .unwrap()
                )
                .is_err());
        }
    }
    for change in 0..5 {
        let mut changed = intent.clone();
        let mut classes = changed.current.plan.classes().to_vec();
        let mut default = changed.current.plan.default_child();
        match change {
            0 => {
                classes[0] =
                    ChildSaClassBinding::new(classes[0].class(), ChildSaId::new(2).unwrap())
            }
            1 => default = ChildSaId::new(1).unwrap(),
            2 => changed.current.pairs.reverse(),
            3 => {
                let pair = &mut changed.current.pairs[0];
                pair.pair = ChildSaPair::new(
                    pair.pair.child(),
                    ChildSaIncarnation::new(97).unwrap(),
                    pair.pair.inbound(),
                    pair.pair.outbound(),
                    pair.pair.outbound_use(),
                );
            }
            4 => {
                classes.pop();
            }
            _ => unreachable!(),
        }
        changed.current.plan = ChildSaSelectionPlan::new(
            changed
                .current
                .pairs
                .iter()
                .map(|p| p.pair.clone())
                .collect(),
            classes,
            default,
            ChildSaSelectionLimits {
                max_pairs: 8,
                max_classes: 256,
            },
        )
        .unwrap();
        assert!(
            store
                .restore_handle(
                    &handle,
                    store
                        .fingerprints_for_child_roster(
                            &changed,
                            &changed.program().unwrap().updated
                        )
                        .unwrap()
                )
                .is_err(),
            "whole context change {change}"
        );
    }
    let mut changed = intent.clone();
    changed.path = Path::new(
        "198.51.100.11:4501".parse().unwrap(),
        "198.51.100.20:4502".parse().unwrap(),
    )
    .unwrap();
    assert!(
        fingerprints
            != store
                .fingerprints_for_child_roster(&changed, &changed.program().unwrap().updated)
                .unwrap()
    );
    let issuing = store
        .transition(
            &handle,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
            Some(XfrmSaRelocationPreEffectProof::RosterWitnessed),
        )
        .unwrap();
    assert!(store.has_unresolved_writer_authority().unwrap());
    assert!(store.advance_writer_epoch().is_err());
    assert_eq!(
        issuing.pre_effect_proof,
        Some(XfrmSaRelocationPreEffectProof::RosterWitnessed)
    );
    assert!(store.restore_handle(&handle, fingerprints).is_err());
}

#[tokio::test]
async fn independent_reference_replays_all_complete_roster_obligations() {
    let table = include_str!("../../tests/fixtures/child-sa-relocation.tsv");
    let mut count = 0;
    for line in table.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 12);
        let name = fields[0];
        let family = fields[1];
        let mut intent = intent(fields[3] == "1");
        if fields[2] == "0" {
            for pair in &mut intent.current.pairs {
                pair.inbound_sa.encap = None;
                pair.outbound_sa.encap = None;
            }
        }
        let program = intent.program().unwrap();
        let ordinal: isize = fields[4].parse().unwrap();
        let after = fields[5] == "1";
        let expected_cut: isize = fields[6].parse().unwrap();
        let expected_mask: isize = fields[7].parse().unwrap();
        let expected_writes: usize = fields[9].parse().unwrap();
        let recovery_writes: isize = fields[10].parse().unwrap();
        let world = World::new(&program);
        match family {
            "mutation-before" | "mutation-after" | "read-before" | "read-after" => {
                world.0.lock().unwrap().fail = Some((ordinal as usize, after));
                assert!(program.finish(&world, || Ok(())).await.is_err(), "{name}");
            }
            "revoked" => {
                let error = program
                    .finish(&world, || {
                        if world.0.lock().unwrap().writes >= ordinal as usize {
                            Err(ChildSaRelocationError::Authentication)
                        } else {
                            Ok(())
                        }
                    })
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, ChildSaRelocationError::Authentication),
                    "{name}"
                );
            }
            "foreign-member" | "missing-member" => {
                {
                    let mut state = world.0.lock().unwrap();
                    let i = ordinal as usize;
                    if i < 8 {
                        if family == "foreign-member" {
                            state.sas[i].auth.as_mut().unwrap().1 =
                                KeyMaterial::new(vec![0xb4; 32]);
                        } else {
                            state.sas.remove(i);
                        }
                    } else if family == "foreign-member" {
                        state.policies[i - 8].priority += 1;
                    } else {
                        state.policies.remove(i - 8);
                    }
                }
                assert!(program.finish(&world, || Ok(())).await.is_err(), "{name}");
            }
            "mixed-members" => {
                let mut state = world.0.lock().unwrap();
                for (i, resource) in program.sas.iter().enumerate() {
                    if expected_mask & (1 << i) != 0 {
                        state.sas[i] = resource.new.clone();
                    }
                }
                for (i, resource) in program.policies.iter().enumerate() {
                    if let Some(block) = &resource.block {
                        state.policies[i] = block.clone();
                    }
                }
            }
            "complete" => program.finish(&world, || Ok(())).await.unwrap(),
            _ => panic!("unknown reference family"),
        }
        assert_eq!(world.0.lock().unwrap().writes, expected_writes, "{name}");
        world.0.lock().unwrap().fail = None;
        let observed = program.prefix(&world).await;
        if expected_cut < 0 {
            assert!(observed.is_err(), "{name}");
            assert!(program.finish(&world, || Ok(())).await.is_err(), "{name}");
            assert_eq!(world.0.lock().unwrap().writes, 0, "{name}");
        } else {
            assert_eq!(observed.unwrap(), expected_cut as usize, "{name}");
            {
                let state = world.0.lock().unwrap();
                for (i, resource) in program.sas.iter().enumerate() {
                    let expected = if expected_mask & (1 << i) != 0 {
                        &resource.new
                    } else {
                        &resource.old
                    };
                    assert!(state.sas[i] == *expected, "{name} SA {i}");
                }
                for (i, phase) in fields[8].bytes().enumerate() {
                    let resource = &program.policies[i];
                    let expected = match phase {
                        b'0' => &resource.old,
                        b'1' => resource.block.as_ref().unwrap(),
                        b'2' => &resource.new,
                        _ => panic!("invalid reference policy state"),
                    };
                    assert_eq!(&state.policies[i], expected, "{name}");
                }
            }
            // Reconstruct from retained physical state, without any in-memory
            // progress from the live run. Only the original intent is reused.
            let restarted = World(Mutex::new(world.0.lock().unwrap().clone()));
            intent
                .program()
                .unwrap()
                .finish(&restarted, || Ok(()))
                .await
                .unwrap();
            assert_eq!(
                restarted.0.lock().unwrap().writes - expected_writes,
                recovery_writes as usize,
                "{name}"
            );
            assert_eq!(program.prefix(&restarted).await.unwrap(), 17, "{name}");
        }
        count += 1;
    }
    assert_eq!(count, 3364);
}
