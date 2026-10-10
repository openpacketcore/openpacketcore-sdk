use super::*;

fn slot(priority: u16, protocol: u16) -> TcSlot {
    TcSlot::new(7, TcHook::Egress, 0, protocol, priority, 1).unwrap()
}
fn hook() -> LocalHookSpec {
    LocalHookSpec::new(
        ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
        ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
    )
    .unwrap()
}
fn topology() -> topology::Topology {
    topology::Topology {
        ifindex: 7,
        clsact: true,
        shared: false,
        hardware: false,
        tcx_count: 0,
        xdp_absent: true,
    }
}
fn dump(filters: &[(u16, u16, u32, [u8; 16])]) -> TcFilterDump {
    let origin = Arc::new(());
    let mut parser = wire::Dump::new(7, TcHook::Egress, 9, 77);
    for (priority, protocol, verdict, cookie) in filters {
        let mut bytes = tests::gact_filter(*verdict, 0, None, 9, 1);
        bytes[32..36].copy_from_slice(
            &((u32::from(*priority) << 16) | u32::from(protocol.to_be())).to_ne_bytes(),
        );
        let at = bytes
            .windows(20)
            .position(|value| value == tests::attr(6, &[0x55; 16]))
            .unwrap();
        bytes[at + 4..at + 20].copy_from_slice(cookie);
        parser.consume(&bytes).unwrap();
    }
    parser.consume(&tests::done()).unwrap();
    TcFilterDump {
        entries: parser
            .finish()
            .unwrap()
            .into_iter()
            .map(|entry| TcFilterIdentity {
                entry,
                origin: Arc::clone(&origin),
            })
            .collect(),
    }
}

#[test]
fn containment_coordinates_require_arp_then_drop_and_disjoint_banks() {
    for (arp, drop) in [
        (slot(1, 3), slot(2, 3)),
        (slot(3, 0x806), slot(2, 3)),
        (slot(1, 0x806), slot(2, 0x800)),
    ] {
        assert_eq!(
            ContainmentBank::new(arp, drop),
            Err(ScopeError::InvalidSpec)
        );
    }
    let a = hook().banks[0];
    assert_eq!(LocalHookSpec::new(a, a), Err(ScopeError::InvalidSpec));
    assert!(LocalScopeSpec::new(
        "/pins".into(),
        "/locks/guard".into(),
        [1; 16],
        vec![hook()],
        vec![slot(2, 3)]
    )
    .is_err());
    assert!(LocalScopeSpec::new(
        "/pins".into(),
        "/locks/guard".into(),
        [1; 16],
        vec![hook()],
        vec![slot(10, 3)]
    )
    .is_ok());
}

#[test]
fn only_complete_exact_banks_prove_coverage() {
    let spec = hook();
    let kernel = topology();
    let cookie = [0x55; 16];
    for filters in [
        vec![],
        vec![(1, 0x806, 0, cookie)],
        vec![(2, 3, 2, cookie)],
        vec![(1, 0x806, 2, cookie), (2, 3, 2, cookie)],
        vec![(1, 0x806, 0, [0x56; 16]), (2, 3, 2, cookie)],
    ] {
        assert!(containment::coverage(spec, cookie, &dump(&filters), &kernel).is_err());
    }
    let one = dump(&[(1, 0x806, 0, cookie), (2, 3, 2, cookie)]);
    assert_eq!(
        containment::coverage(spec, cookie, &one, &kernel).unwrap(),
        [true, false]
    );
    let both = dump(&[
        (1, 0x806, 0, cookie),
        (2, 3, 2, cookie),
        (3, 0x806, 0, cookie),
        (4, 3, 2, cookie),
    ]);
    assert_eq!(
        containment::coverage(spec, cookie, &both, &kernel).unwrap(),
        [true, true]
    );
}

#[test]
fn bypasses_and_unverified_alternates_refuse_coverage() {
    let spec = hook();
    let cookie = [0x55; 16];
    let closed = dump(&[(1, 0x806, 0, cookie), (2, 3, 2, cookie)]);
    for change in 0..5 {
        let mut kernel = topology();
        match change {
            0 => kernel.ifindex = 8,
            1 => kernel.clsact = false,
            2 => kernel.shared = true,
            3 => kernel.hardware = true,
            _ => kernel.tcx_count = 1,
        }
        assert!(containment::coverage(spec, cookie, &closed, &kernel).is_err());
    }
    let partial_alternate = dump(&[
        (1, 0x806, 0, cookie),
        (3, 0x806, 0, cookie),
        (4, 3, 2, cookie),
    ]);
    assert!(containment::coverage(spec, cookie, &partial_alternate, &topology()).is_err());
    let equal_priority_foreign = dump(&[
        (1, 0x806, 0, cookie),
        (2, 3, 2, cookie),
        (2, 0x800, 0, [0x66; 16]),
    ]);
    assert!(containment::coverage(spec, cookie, &equal_priority_foreign, &topology()).is_err());
}

fn link(xdp: Option<Vec<u8>>) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&1_u16.to_ne_bytes());
    body[4..8].copy_from_slice(&7_u32.to_ne_bytes());
    body.extend(tests::attr(3, b"scope0\0"));
    body.extend(tests::attr(1, &[0x12, 0x34, 0x56, 0x78, 0x90, 0xab]));
    if let Some(xdp) = xdp {
        body.extend(tests::attr(43, &xdp));
    }
    tests::message(16, 0, &body)
}
fn qdisc(extra: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 20];
    body[4..8].copy_from_slice(&7_u32.to_ne_bytes());
    body[8..12].copy_from_slice(&0xffff0000_u32.to_ne_bytes());
    body[12..16].copy_from_slice(&0xfffffff1_u32.to_ne_bytes());
    body.extend(tests::attr(1, b"clsact\0"));
    body.extend(extra);
    tests::message(36, 2, &body)
}

#[test]
fn link_readback_requires_identity_and_all_xdp_modes_absent() {
    let (identity, absent) = topology::parse_link(&link(Some(tests::attr(2, &[0]))), 7).unwrap();
    assert_eq!(identity.kind, 1);
    assert!(absent);
    for xdp in [
        None,
        Some(tests::attr(2, &[1])),
        Some([tests::attr(2, &[0]), tests::attr(7, &42_u32.to_ne_bytes())].concat()),
        Some([tests::attr(2, &[0]), tests::attr(31, &[0])].concat()),
    ] {
        assert!(!topology::parse_link(&link(xdp), 7).unwrap().1);
    }
    assert!(topology::parse_link(&link(Some(tests::attr(2, &[0]))), 8).is_err());
    assert!(topology::parse_link(
        &link(Some([tests::attr(2, &[0]), tests::attr(2, &[0])].concat())),
        7
    )
    .is_err());
}

#[test]
fn qdisc_readback_rejects_shared_blocks_and_detects_hardware() {
    assert_eq!(
        topology::parse_qdisc(&qdisc(&[]), 7).unwrap(),
        (true, false, false)
    );
    for key in [13, 14] {
        assert_eq!(
            topology::parse_qdisc(&qdisc(&tests::attr(key, &5_u32.to_ne_bytes())), 7).unwrap(),
            (true, true, false)
        );
    }
    assert_eq!(
        topology::parse_qdisc(&qdisc(&tests::attr(12, &[1])), 7).unwrap(),
        (true, false, true)
    );
    assert!(topology::parse_qdisc(&qdisc(&[]), 8).is_err());
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
#[test]
#[ignore = "requires explicit private-netns root qualification"]
fn private_netns_topology_checks_native_qdisc_tcx_and_xdp() {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
        std::fs::metadata("/proc/1/ns/net").unwrap().ino()
    );
    let mut tc = TcClient::new().unwrap();
    let (before, xdp_absent) = topology::inspect_link(&mut tc, 1).unwrap();
    assert!(xdp_absent);
    assert!(!topology::inspect_qdisc(&mut tc, 1).unwrap().0);
    topology::ensure_clsact(&mut tc, 1).unwrap();
    assert_eq!(
        topology::inspect_qdisc(&mut tc, 1).unwrap(),
        (true, false, false)
    );
    assert_eq!(crate::platform::tcx_program_count(1, true).unwrap(), 0);
    assert_eq!(crate::platform::tcx_program_count(1, false).unwrap(), 0);
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "dev", "lo", "alias", "replacement"])
        .status()
        .unwrap()
        .success());
    assert_ne!(topology::inspect_link(&mut tc, 1).unwrap().0, before);
}

struct Model {
    filters: Vec<TcFilterIdentity>,
    topology: topology::Topology,
    identity: topology::InterfaceIdentity,
    refusal: Option<ScopeError>,
    topology_refusal: Option<ScopeError>,
    topology_reads: Vec<TcHook>,
    qdisc_creates: usize,
    lose_create: Option<TcSlot>,
    lose_delete: Option<TcSlot>,
    corrupt_alternate_after_delete: bool,
    events: Vec<(bool, TcSlot)>,
}
struct ModelKernel(Arc<std::sync::Mutex<Model>>);
impl scope::Kernel for ModelKernel {
    fn verify(&self) -> Result<(), ScopeError> {
        self.0.lock().unwrap().refusal.map_or(Ok(()), Err)
    }
    fn interface(&mut self, _ifindex: u32) -> Result<topology::InterfaceIdentity, ScopeError> {
        Ok(self.0.lock().unwrap().identity.clone())
    }
    fn topology(&mut self, spec: LocalHookSpec) -> Result<topology::Topology, ScopeError> {
        let mut model = self.0.lock().unwrap();
        model.topology_reads.push(spec.hook());
        model
            .topology_refusal
            .map_or_else(|| Ok(model.topology.clone()), Err)
    }
    fn ensure_clsact(&mut self, _ifindex: u32) -> Result<(), ScopeError> {
        let mut model = self.0.lock().unwrap();
        model.topology.clsact = true;
        model.qdisc_creates += 1;
        Ok(())
    }
    fn dump(&mut self, spec: LocalHookSpec) -> Result<TcFilterDump, ScopeError> {
        Ok(TcFilterDump {
            entries: self
                .0
                .lock()
                .unwrap()
                .filters
                .iter()
                .filter(|filter| {
                    filter.slot().ifindex() == spec.ifindex() && filter.slot().hook() == spec.hook()
                })
                .cloned()
                .collect(),
        })
    }
    fn create(
        &mut self,
        slot: TcSlot,
        cookie: [u8; 16],
        verdict: TcVerdict,
    ) -> Result<(), ScopeError> {
        let mut model = self.0.lock().unwrap();
        if model.filters.iter().any(|filter| filter.slot() == slot) {
            return Err(ScopeError::Conflict);
        }
        let verdict = match verdict {
            TcVerdict::Pass => 0,
            TcVerdict::Drop => 2,
        };
        let entry = dump(&[(slot.priority, slot.protocol, verdict, cookie)])
            .entries
            .remove(0);
        model.filters.push(entry);
        model.events.push((true, slot));
        if model.lose_create == Some(slot) {
            model.lose_create = None;
            return Err(ScopeError::Inspection);
        }
        Ok(())
    }
    fn delete(&mut self, expected: &TcFilterIdentity) -> Result<(), ScopeError> {
        let mut model = self.0.lock().unwrap();
        let index = model
            .filters
            .iter()
            .position(|actual| {
                actual.entry == expected.entry && Arc::ptr_eq(&actual.origin, &expected.origin)
            })
            .ok_or(ScopeError::Conflict)?;
        model.filters.remove(index);
        model.events.push((false, expected.slot()));
        if model.lose_delete == Some(expected.slot()) {
            model.lose_delete = None;
            return Err(ScopeError::Inspection);
        }
        if model.corrupt_alternate_after_delete {
            model.corrupt_alternate_after_delete = false;
            let altered = dump(&[(3, 0x806, 0, [0x66; 16])]).entries.remove(0);
            model
                .filters
                .iter_mut()
                .find(|entry| entry.slot() == slot(3, 0x806))
                .unwrap()
                .entry = altered.entry;
        }
        Ok(())
    }
}
fn driver() -> (scope::Driver, Arc<std::sync::Mutex<Model>>) {
    let spec = LocalScopeSpec::new(
        "/pins".into(),
        "/locks/guard".into(),
        [0x55; 16],
        vec![hook()],
        vec![slot(10, 3)],
    )
    .unwrap();
    let model = Arc::new(std::sync::Mutex::new(Model {
        filters: dump(&[(10, 3, 0, [0x77; 16])]).entries,
        topology: topology(),
        identity: topology::parse_link(&link(Some(tests::attr(2, &[0]))), 7)
            .unwrap()
            .0,
        refusal: None,
        topology_refusal: None,
        topology_reads: Vec::new(),
        qdisc_creates: 0,
        lose_create: None,
        lose_delete: None,
        corrupt_alternate_after_delete: false,
        events: Vec::new(),
    }));
    let driver = scope::Driver::new(spec, Box::new(ModelKernel(Arc::clone(&model)))).unwrap();
    (driver, model)
}

#[test]
fn readonly_inspection_distinguishes_empty_data_complete_and_every_partial_bank() {
    let cookie = [0x55; 16];
    for mask in 0_u8..16 {
        for data in [false, true] {
            let (mut driver, model) = driver();
            let roles = [
                (1, 0x806, 0, cookie),
                (2, 3, 2, cookie),
                (3, 0x806, 0, cookie),
                (4, 3, 2, cookie),
            ];
            let mut filters = roles
                .into_iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, role)| role)
                .collect::<Vec<_>>();
            if data {
                filters.push((10, 3, 0, [0x77; 16]));
            }
            model.lock().unwrap().filters = dump(&filters).entries;
            model.lock().unwrap().topology.clsact = mask != 0 || data;
            let before = model
                .lock()
                .unwrap()
                .filters
                .iter()
                .map(|filter| filter.entry.clone())
                .collect::<Vec<_>>();
            let observed = driver.inspect().unwrap();
            let expected = match mask {
                0 => ContainmentInspection::Absent,
                3 | 12 | 15 => ContainmentInspection::OwnedAndContained,
                _ => ContainmentInspection::OwnedPartial,
            };
            assert_eq!(observed.containment(), expected, "bank mask {mask}");
            assert_eq!(observed.is_empty(), mask == 0 && !data, "bank mask {mask}");
            let after = model.lock().unwrap();
            assert_eq!(
                after
                    .filters
                    .iter()
                    .map(|filter| filter.entry.clone())
                    .collect::<Vec<_>>(),
                before
            );
            assert!(after.events.is_empty());
            assert_eq!(after.qdisc_creates, 0);
            assert_eq!(after.topology_reads, [TcHook::Egress]);
        }
    }
}

#[test]
fn readonly_inspection_checks_all_hooks_and_reports_incomplete_scope_coverage() {
    let (mut driver, model) = driver();
    let mut ingress = hook();
    for bank in &mut ingress.banks {
        bank.arp.hook = TcHook::Ingress;
        bank.drop.hook = TcHook::Ingress;
    }
    driver.spec.hooks.push(ingress);
    model.lock().unwrap().filters =
        dump(&[(1, 0x806, 0, [0x55; 16]), (2, 3, 2, [0x55; 16])]).entries;
    assert_eq!(
        driver.inspect().unwrap().containment(),
        ContainmentInspection::OwnedPartial
    );
    let mut additional = model.lock().unwrap().filters.clone();
    for filter in &mut additional {
        filter.entry.slot.hook = TcHook::Ingress;
    }
    model.lock().unwrap().filters.extend(additional);
    assert_eq!(
        driver.inspect().unwrap().containment(),
        ContainmentInspection::OwnedAndContained
    );
    let state = model.lock().unwrap();
    assert_eq!(
        state.topology_reads,
        [
            TcHook::Egress,
            TcHook::Ingress,
            TcHook::Egress,
            TcHook::Ingress
        ]
    );
    assert!(state.events.is_empty());
    assert_eq!(state.qdisc_creates, 0);
}

#[test]
fn readonly_inspection_refuses_unsupported_and_bypasses_even_without_banks() {
    for case in 0..7 {
        let (mut driver, model) = driver();
        model.lock().unwrap().filters.clear();
        model.lock().unwrap().topology.clsact = false;
        let expected = match case {
            0 => {
                model.lock().unwrap().topology_refusal = Some(ScopeError::Unsupported);
                ScopeError::Unsupported
            }
            1 => {
                model.lock().unwrap().topology_refusal = Some(ScopeError::Inspection);
                ScopeError::Inspection
            }
            2 => {
                model.lock().unwrap().topology.tcx_count = 1;
                ScopeError::Coverage
            }
            3 => {
                model.lock().unwrap().topology.shared = true;
                ScopeError::Coverage
            }
            4 => {
                model.lock().unwrap().topology.hardware = true;
                ScopeError::Coverage
            }
            5 => {
                model.lock().unwrap().topology.ifindex = 8;
                ScopeError::Coverage
            }
            _ => {
                for bank in &mut driver.spec.hooks[0].banks {
                    bank.arp.hook = TcHook::Ingress;
                    bank.drop.hook = TcHook::Ingress;
                }
                model.lock().unwrap().topology.xdp_absent = false;
                ScopeError::Coverage
            }
        };
        assert_eq!(driver.inspect(), Err(expected), "case {case}");
        let state = model.lock().unwrap();
        assert!(state.events.is_empty());
        assert_eq!(state.qdisc_creates, 0);
    }
}

#[test]
fn readonly_inspection_never_treats_foreign_or_malformed_banks_as_owned_partial() {
    for (filters, expected) in [
        (
            vec![(1, 0x806, 0, [0x56; 16])],
            ScopeError::OwnerCookieMismatch,
        ),
        (vec![(1, 0x806, 2, [0x55; 16])], ScopeError::Conflict),
        (vec![(2, 3, 0, [0x55; 16])], ScopeError::Conflict),
        (vec![(1, 0x800, 0, [0x55; 16])], ScopeError::Coverage),
    ] {
        let (mut driver, model) = driver();
        model.lock().unwrap().filters = dump(&filters).entries;
        assert_eq!(driver.inspect(), Err(expected));
        assert!(model.lock().unwrap().events.is_empty());
        assert_eq!(model.lock().unwrap().qdisc_creates, 0);
    }
}

#[test]
fn opening_removes_only_owned_filters_and_never_uses_an_old_data_snapshot() {
    let (mut driver, model) = driver();
    let data = model.lock().unwrap().filters.clone();
    driver.contain().unwrap();
    let foreign = dump(&[(90, 3, 0, [0x88; 16])]).entries.remove(0);
    model.lock().unwrap().filters.push(foreign.clone());
    assert!(!driver.open_next(&data).unwrap());
    assert!(!driver.open_next(&data).unwrap());
    assert!(driver.open_next(&data).unwrap());
    assert_eq!(model.lock().unwrap().filters.len(), 2);
    assert!(model
        .lock()
        .unwrap()
        .filters
        .iter()
        .any(|actual| actual.entry == foreign.entry));
    assert_eq!(
        &model.lock().unwrap().events[2..],
        &[(false, slot(2, 3)), (false, slot(1, 0x806))]
    );
    driver.contain().unwrap();
    let changed = dump(&[(10, 3, 0, [0x99; 16])]).entries.remove(0);
    model.lock().unwrap().filters[0] = changed;
    let before = model.lock().unwrap().events.len();
    assert!(driver.open_next(&data).is_err());
    assert_eq!(model.lock().unwrap().events.len(), before);
    driver.recheck().unwrap();
}

#[test]
fn a_predecessor_cookie_mismatch_is_a_typed_refusal_before_containment_mutation() {
    // The predecessor-bank review probe now asserts the decided typed refusal,
    // rather than treating a permanently blocked bank as successful behavior.
    let predecessor = dump(&[(1, 0x806, 0, [0x56; 16]), (2, 3, 2, [0x56; 16])]);
    assert!(containment::coverage(hook(), [0x55; 16], &predecessor, &topology()).is_err());
    assert!(!containment::can_install(
        hook(),
        [0x55; 16],
        0,
        &predecessor
    ));
    assert!(!containment::can_install(
        hook(),
        [0x55; 16],
        1,
        &predecessor
    ));
    let (mut driver, model) = driver();
    model
        .lock()
        .unwrap()
        .filters
        .extend(dump(&[(1, 0x806, 0, [0x56; 16]), (2, 3, 2, [0x56; 16])]).entries);
    assert_eq!(driver.contain(), Err(ScopeError::OwnerCookieMismatch));
    assert!(model.lock().unwrap().events.is_empty());
}

#[test]
fn opening_refuses_foreign_precedence_without_removing_containment() {
    for priority in [1, 2, 3, 4] {
        let (mut driver, model) = driver();
        let data = model.lock().unwrap().filters.clone();
        driver.contain().unwrap();
        // A different EtherType keeps this outside both banks' exact slots,
        // while its priority can precede or equal their protective drop.
        let foreign = dump(&[(priority, 0x800, 0, [0x88; 16])]).entries.remove(0);
        model.lock().unwrap().filters.push(foreign);
        let before = model.lock().unwrap().events.clone();
        assert_eq!(driver.open_next(&data), Err(ScopeError::Coverage));
        assert_eq!(model.lock().unwrap().events, before);
    }
}

#[test]
fn lost_open_ack_requires_verified_recontainment_before_retry() {
    let (mut driver, model) = driver();
    let data = model.lock().unwrap().filters.clone();
    driver.contain().unwrap();
    model.lock().unwrap().lose_delete = Some(slot(2, 3));
    assert!(driver.open_next(&data).is_err());
    assert!(driver.recheck().is_err());
    driver.contain().unwrap();
    driver.recheck().unwrap();
    assert!(!driver.open_next(&data).unwrap());
    assert!(!driver.open_next(&data).unwrap());
    assert!(driver.open_next(&data).unwrap());
}

#[test]
fn production_driver_closes_arp_first_and_rechecks_before_data_removal() {
    let (mut driver, model) = driver();
    let data = driver.inventory().unwrap().remove(0).entries.remove(0);
    assert!(driver.delete_data(&data).is_err());
    driver.contain().unwrap();
    assert_eq!(
        model.lock().unwrap().events,
        vec![(true, slot(1, 0x806)), (true, slot(2, 3))]
    );
    model.lock().unwrap().topology.tcx_count = 1;
    assert!(driver.delete_data(&data).is_err());
    assert_eq!(model.lock().unwrap().events.len(), 2);
    model.lock().unwrap().topology.tcx_count = 0;
    driver.delete_data(&data).unwrap();
    assert_eq!(
        model.lock().unwrap().events.last(),
        Some(&(false, slot(10, 3)))
    );
}

#[test]
fn production_driver_establishes_alternate_before_replacing_bank() {
    let (mut driver, model) = driver();
    driver.contain().unwrap();
    driver.replace_bank(7, TcHook::Egress, 0).unwrap();
    assert_eq!(
        model.lock().unwrap().events,
        vec![
            (true, slot(1, 0x806)),
            (true, slot(2, 3)),
            (true, slot(3, 0x806)),
            (true, slot(4, 3)),
            (false, slot(2, 3)),
            (false, slot(1, 0x806)),
            (true, slot(1, 0x806)),
            (true, slot(2, 3)),
        ]
    );
    driver.recheck().unwrap();
}

#[test]
fn driver_refuses_changed_handles_devices_and_bypasses_before_effects() {
    for case in 0..4 {
        let (mut driver, model) = driver();
        match case {
            0 => model.lock().unwrap().refusal = Some(ScopeError::LockChanged),
            1 => model
                .lock()
                .unwrap()
                .identity
                .configuration
                .push((20, b"changed".to_vec())),
            2 => model.lock().unwrap().topology.tcx_count = 1,
            _ => model.lock().unwrap().topology.shared = true,
        }
        assert!(driver.inspect().is_err());
        assert!(driver.contain().is_err());
        assert!(model.lock().unwrap().events.is_empty());
    }
}

#[test]
fn lost_containment_ack_requires_readback_and_exact_retry() {
    let (mut driver, model) = driver();
    model.lock().unwrap().lose_create = Some(slot(2, 3));
    assert!(driver.contain().is_err());
    driver.contain().unwrap();
    driver.recheck().unwrap();
    assert_eq!(model.lock().unwrap().events.len(), 2);
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
#[test]
#[ignore = "requires explicit private mount/netns root qualification"]
fn private_namespace_scope_retains_lock_across_bpffs_replacement() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    for namespace in ["net", "mnt"] {
        assert_ne!(
            std::fs::metadata(format!("/proc/thread-self/ns/{namespace}"))
                .unwrap()
                .ino(),
            std::fs::metadata(format!("/proc/1/ns/{namespace}"))
                .unwrap()
                .ino()
        );
    }
    struct Mount {
        path: PathBuf,
        count: usize,
    }
    impl Mount {
        fn add(&mut self) {
            assert!(Command::new("mount")
                .args(["-t", "bpf", "-o", "mode=700", "bpf"])
                .arg(self.path.join("pins"))
                .status()
                .unwrap()
                .success());
            self.count += 1;
        }
    }
    impl Drop for Mount {
        fn drop(&mut self) {
            for _ in 0..self.count {
                let _ = Command::new("umount").arg(self.path.join("pins")).status();
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    let path = std::env::temp_dir().join(format!("opc-scope-native-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(path.join("pins")).unwrap();
    let mut mount = Mount { path, count: 0 };
    mount.add();
    let position =
        |priority, protocol| TcSlot::new(1, TcHook::Egress, 0, protocol, priority, 1).unwrap();
    let a = ContainmentBank::new(position(1, 0x806), position(2, 3)).unwrap();
    let b = ContainmentBank::new(position(3, 0x806), position(4, 3)).unwrap();
    let spec = LocalScopeSpec::new(
        mount.path.join("pins"),
        mount.path.join("lock"),
        [0x33; 16],
        vec![LocalHookSpec::new(a, b).unwrap()],
        Vec::new(),
    )
    .unwrap();
    let scope = LocalKernelScope::open(spec.clone()).unwrap();
    let lock_inode = std::fs::metadata(mount.path.join("lock")).unwrap().ino();
    assert!(matches!(
        LocalKernelScope::open(spec.clone()),
        Err(ScopeError::Busy)
    ));
    assert!(scope.inventory().unwrap()[0].entries().is_empty());
    let closed = scope.contain().unwrap();
    closed.recheck().unwrap();
    assert_eq!(
        scope.inventory().unwrap()[0]
            .entries()
            .iter()
            .filter(|entry| !entry.is_summary())
            .count(),
        2
    );
    closed.replace_bank(1, TcHook::Egress, 0).unwrap();
    closed.recheck().unwrap();
    mount.add();
    assert_eq!(scope.verify(), Err(ScopeError::RootChanged));
    assert!(matches!(
        LocalKernelScope::open(spec.clone()),
        Err(ScopeError::Busy)
    ));
    drop(closed);
    drop(scope);
    let restarted = LocalKernelScope::open(spec).unwrap();
    restarted.contain().unwrap().recheck().unwrap();
    assert_eq!(
        std::fs::metadata(mount.path.join("lock")).unwrap().ino(),
        lock_inode
    );
    drop(restarted);
}

#[test]
fn ingress_xdp_and_unknown_classifier_summaries_cannot_be_ignored() {
    let cookie = [0x55; 16];
    let mut spec = hook();
    for bank in &mut spec.banks {
        bank.arp.hook = TcHook::Ingress;
        bank.drop.hook = TcHook::Ingress;
    }
    let mut observed = dump(&[(1, 0x806, 0, cookie), (2, 3, 2, cookie)]);
    for filter in &mut observed.entries {
        filter.entry.slot.hook = TcHook::Ingress;
    }
    let mut kernel = topology();
    kernel.xdp_absent = false;
    assert!(containment::inspect(spec, cookie, &[], &observed, &kernel).is_err());
    assert!(containment::coverage(spec, cookie, &observed, &kernel).is_err());
    kernel.xdp_absent = true;
    assert!(containment::coverage(spec, cookie, &observed, &kernel).is_ok());
    let mut bytes = tests::filter(0, 3, 0);
    // Same length as bpf, but an unknown classifier may lack an enumerable
    // filter walk. A summary cannot then prove that no effects are present.
    bytes[40..44].copy_from_slice(b"new\0");
    let mut parser = wire::Dump::new(7, TcHook::Egress, 9, 77);
    parser.consume(&bytes).unwrap();
    parser.consume(&tests::done()).unwrap();
    let mut closed = dump(&[(1, 0x806, 0, cookie), (2, 3, 2, cookie)]);
    closed.entries.extend(
        parser
            .finish()
            .unwrap()
            .into_iter()
            .map(|entry| TcFilterIdentity {
                entry,
                origin: Arc::new(()),
            }),
    );
    assert!(containment::coverage(hook(), cookie, &closed, &kernel).is_err());
    assert!(containment::inspect(hook(), cookie, &[], &closed, &kernel).is_err());
}

#[test]
fn hardware_filter_on_later_priority_blocks_containment_before_creation() {
    let (mut driver, model) = driver();
    let mut bytes = tests::gact_filter(0, 0, None, 5, 1);
    bytes[32..36].copy_from_slice(&((10_u32 << 16) | u32::from(3_u16.to_be())).to_ne_bytes());
    let mut parser = wire::Dump::new(7, TcHook::Egress, 9, 77);
    parser.consume(&bytes).unwrap();
    parser.consume(&tests::done()).unwrap();
    model.lock().unwrap().filters[0].entry = parser.finish().unwrap().remove(0);
    assert!(driver.inspect().is_err());
    assert!(driver.contain().is_err());
    assert!(model.lock().unwrap().events.is_empty());
}

#[test]
fn alternate_change_stops_bank_retirement_before_next_component() {
    let (mut driver, model) = driver();
    driver.contain().unwrap();
    model.lock().unwrap().corrupt_alternate_after_delete = true;
    assert!(driver.replace_bank(7, TcHook::Egress, 0).is_err());
    assert_eq!(
        model.lock().unwrap().events.last(),
        Some(&(false, slot(2, 3)))
    );
    assert!(model
        .lock()
        .unwrap()
        .filters
        .iter()
        .any(|entry| entry.slot() == slot(1, 0x806)));
    // A changed installation cookie refuses retry without touching either
    // bank. Only restoration of the owned identity permits partial-bank repair.
    let effects = model.lock().unwrap().events.len();
    assert_eq!(driver.contain(), Err(ScopeError::OwnerCookieMismatch));
    assert_eq!(model.lock().unwrap().events.len(), effects);
    model
        .lock()
        .unwrap()
        .filters
        .iter_mut()
        .find(|entry| entry.slot() == slot(3, 0x806))
        .unwrap()
        .entry = dump(&[(3, 0x806, 0, [0x55; 16])]).entries.remove(0).entry;
    driver.contain().unwrap();
    driver.recheck().unwrap();
}

#[cfg(any(not(target_os = "linux"), opc_linux_gtpu_sys_force_unsupported))]
#[test]
fn unsupported_platform_never_constructs_a_local_guard() {
    let spec = LocalScopeSpec::new(
        "/pins".into(),
        "/locks/guard".into(),
        [1; 16],
        vec![hook()],
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        LocalKernelScope::open(spec),
        Err(ScopeError::Unsupported)
    ));
    assert_eq!(
        crate::platform::tcx_program_count(7, true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn reset_preflight_driver_calls_never_query_tcx() {
    let (mut driver, model) = driver();
    model.lock().unwrap().topology_refusal = Some(ScopeError::Unsupported);
    model.lock().unwrap().topology_reads.clear();
    assert!(
        driver.inventory().is_ok(),
        "the owner-check inventory succeeds"
    );
    assert!(
        model.lock().unwrap().topology_reads.is_empty(),
        "the preflight path read topology"
    );
    assert_eq!(driver.contain(), Err(ScopeError::Unsupported));
    let state = model.lock().unwrap();
    assert!(!state.topology_reads.is_empty());
    assert!(state.events.is_empty());
    assert_eq!(state.qdisc_creates, 0);
}

#[test]
fn readonly_inspection_distinguishes_declared_data_from_foreign_filters() {
    for data in [false, true] {
        for foreign in [false, true] {
            let (mut driver, model) = driver();
            let mut filters = Vec::new();
            if data {
                filters.push((10, 3, 0, [0x77; 16]));
            }
            if foreign {
                filters.push((20, 3, 0, [0x88; 16]));
            }
            model.lock().unwrap().filters = dump(&filters).entries;
            let observed = driver.inspect().unwrap();
            assert_eq!(observed.containment(), ContainmentInspection::Absent);
            assert_eq!(observed.foreign_filters_present(), foreign);
            assert_eq!(observed.is_empty(), !data && !foreign);
            let state = model.lock().unwrap();
            assert!(state.events.is_empty());
            assert_eq!(state.qdisc_creates, 0);
        }
    }
}
