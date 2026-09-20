use super::*;

// Interpose only after the real protected namespace binding has succeeded.
// This separates adapter stamp enforcement from the coordinator's earlier
// complete-inventory check; otherwise that check masks a removed adapter guard.
#[derive(Debug)]
struct ChangedStampAfterBinding {
    backend: Arc<EbpfGtpuDataplaneBackend>,
    pin_dir: PathBuf,
    byte: usize,
    entered: AtomicUsize,
}

#[async_trait::async_trait]
impl GtpuDataplaneBackend for ChangedStampAfterBinding {
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        self.backend.create_device(request).await
    }
    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError> {
        self.backend.resolve_device(name).await
    }
    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        self.backend.remove_device(device).await
    }
    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        self.backend.install_pdp_context(request).await
    }
    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        self.backend.remove_pdp_context(request).await
    }
    async fn probe(&self) -> Result<opc_gtpu_dataplane::GtpuProbe, GtpuError> {
        self.backend.probe().await
    }
    async fn acquire_selector_namespace_lease(
        &self,
        lease: opc_gtpu_dataplane::GtpuSessionSelectorBindingLease,
    ) -> Result<opc_gtpu_dataplane::GtpuSessionSelectorBackendReceipt, GtpuError> {
        self.backend.acquire_selector_namespace_lease(lease).await
    }
    async fn submit_n3_end_markers(
        &self,
        request: opc_gtpu_dataplane::GtpuN3EndMarkerRequest,
    ) -> Result<opc_gtpu_dataplane::GtpuN3EndMarkerReceipt, GtpuError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let map = Map::from_map_data(
            MapData::from_pin(self.pin_dir.join(MAP_SESSION_SELECTOR_STAMPS)).unwrap(),
        )
        .unwrap();
        let mut stamps = BpfHashMap::<
            _,
            [u8; GTPU_SESSION_GROUP_ID_LEN],
            [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
        >::try_from(map)
        .unwrap();
        let key = request.retired_group().id().to_bytes();
        let exact = stamps.get(&key, 0).unwrap();
        let mut changed = exact;
        changed[self.byte] ^= 1;
        stamps.insert(key, changed, 0).unwrap();
        let result = self.backend.submit_n3_end_markers(request).await;
        stamps.insert(key, exact, 0).unwrap();
        result
    }
}

// The independent End Marker oracle is the eight-byte TS 29.281 envelope.
// Neither the SDK control codec nor its output is used to construct it.
fn marker(teid: u32) -> Vec<u8> {
    let mut wire = vec![0x30, 0xfe, 0, 0];
    wire.extend_from_slice(&teid.to_be_bytes());
    wire
}

fn receive(socket: &UdpSocket) -> Vec<u8> {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut wire = vec![0; 65536];
    let (len, peer) = socket
        .recv_from(&mut wire)
        .expect("receive ordered N3 datagram");
    assert_eq!(peer, SocketAddr::from((EPDG_S2BU_IP, GTPU_PORT)));
    wire.truncate(len);
    wire
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for shared_peer_tunnel in [false, true] {
        let net = TestNet::provision();
        let config = EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        };
        let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(config.clone()));
        let device = backend
            .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
            .await?;
        let old = initial_grouped_session(device.ifindex);
        let entries = old
            .entries()
            .iter()
            .enumerate()
            .map(|(index, base)| {
                let mut context = base.context().clone();
                context.peer_address = IpAddr::V4(PGW_IP);
                if shared_peer_tunnel {
                    context.peer_teid = old.entries()[0].context().peer_teid;
                }
                let base = GtpuSessionEntry::new(context, IpAddr::V4(EPDG_S2BU_IP)).unwrap();
                n3_fixed_flow::entry(&base, if index == 0 { 0 } else { 63 })
            })
            .collect();
        let desired = GtpuSessionGroup::new(old.id(), old.device_id(), entries)?;
        let (namespace, active) = reconcile_fresh_grouped(backend.clone(), desired.clone()).await?;
        run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
        let peer = in_netns(&net.pgw_ns, || {
            UdpSocket::bind((PGW_IP, GTPU_PORT)).unwrap()
        });
        let pin_dir = grouped_pin_directory(&net.pin_root, grouped_device_id());
        let active_graph = pinned_hash_entries::<
            GTPU_SESSION_GROUP_ID_LEN,
            GTPU_SESSION_GROUP_VALUE_LEN,
        >(&pin_dir, MAP_SESSION_GROUPS);
        let active_uplink = pinned_hash_entries::<
            GTPU_SESSION_UPLINK_KEY_LEN,
            GTPU_SESSION_GROUP_REF_LEN,
        >(&pin_dir, MAP_SESSION_UPLINK_INDEX);
        let active_downlink = pinned_hash_entries::<
            GTPU_SESSION_DOWNLINK_KEY_LEN,
            GTPU_SESSION_GROUP_REF_LEN,
        >(&pin_dir, MAP_SESSION_DOWNLINK_INDEX);
        assert_eq!(active_graph.len(), 1);
        assert_eq!(active_uplink.len(), 2);
        assert_eq!(active_downlink.len(), 2);
        let redirects_before = pinned_counter(&pin_dir, COUNTER_UL_REDIRECT_RESOLVED);
        let mut expected = Vec::new();
        for sequence in 0..3 {
            for (index, entry) in desired.entries().iter().enumerate() {
                let inner = n3_fixed_flow::uplink_inner(&net, index == 1, &[sequence]);
                expected.push(n3_fixed_flow::gpdu(
                    entry.context().peer_teid.get(),
                    entry.n3_qfi().unwrap().get(),
                    true,
                    &inner,
                ));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while pinned_counter(&pin_dir, COUNTER_UL_REDIRECT_RESOLVED) < redirects_before + 6 {
            assert!(
                Instant::now() < deadline,
                "six GPDU redirects must precede retirement"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let retired = namespace
            .retire(backend.clone(), active, desired.clone())
            .await?;

        // Lose the process-local backend before submission: adoption must bind
        // the same retained terminal stamp and original outgoing UDP tuple.
        drop(backend);
        let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(config));
        let adopted = backend
            .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
            .await?;
        assert_eq!(adopted, device);
        let control = backend.open_gtpu_control_port(&adopted).await?;
        // Pre-open the sole managed socket and queue an independently authored
        // Echo Request. End Marker submission must neither bind a competing
        // UDP socket nor consume this incoming control from the shared queue.
        let echo = [0x32, 1, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
        peer.send_to(&echo, (EPDG_S2BU_IP, GTPU_PORT))?;
        let completion = namespace
            .send_n3_end_markers(backend.clone(), retired)
            .await?;
        let count = if shared_peer_tunnel { 1 } else { 2 };
        assert_eq!(completion.datagram_count(), count);

        // Leave all six GPDUs queued at the independent peer until submission
        // completes, then prove the markers follow them in the received stream.
        // Cross-family GPDU order is not prescribed; the marker boundary is.
        let mut observed = (0..6).map(|_| receive(&peer)).collect::<Vec<_>>();
        expected.sort();
        observed.sort();
        assert_eq!(observed, expected);
        let mut markers = (0..count).map(|_| receive(&peer)).collect::<Vec<_>>();
        let mut expected_markers = desired
            .entries()
            .iter()
            .map(|entry| marker(entry.context().peer_teid.get()))
            .collect::<Vec<_>>();
        markers.sort();
        expected_markers.sort();
        expected_markers.dedup();
        assert_eq!(markers, expected_markers);
        let deadline = Instant::now() + Duration::from_secs(2);
        let datagram = loop {
            if let Some(datagram) = control.try_receive_datagram(256)? {
                break datagram;
            }
            assert!(
                Instant::now() < deadline,
                "managed receive queue lost the Echo Request"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(datagram.bytes(), echo);
        assert_eq!(
            datagram.peer(),
            std::net::SocketAddrV4::new(PGW_IP, GTPU_PORT)
        );
        assert_eq!(
            datagram.local(),
            std::net::SocketAddrV4::new(EPDG_S2BU_IP, GTPU_PORT)
        );
        for inner6 in [false, true] {
            n3_fixed_flow::uplink_inner(&net, inner6, b"after-retirement");
        }
        expect_no_datagram(&peer);

        let stamp_map = Map::from_map_data(MapData::from_pin(
            pin_dir.join(MAP_SESSION_SELECTOR_STAMPS),
        )?)?;
        let mut stamps = BpfHashMap::<
            _,
            [u8; GTPU_SESSION_GROUP_ID_LEN],
            [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
        >::try_from(stamp_map)?;
        let key = desired.id().to_bytes();
        let exact = stamps.get(&key, 0)?;
        for byte in 0..GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN {
            let request = namespace
                .recover_retired(backend.clone(), desired.clone())
                .await?;
            let mut wrong = exact;
            wrong[byte] ^= 1;
            stamps.insert(key, wrong, 0)?;
            let result = namespace
                .send_n3_end_markers(backend.clone(), request)
                .await;
            stamps.insert(key, exact, 0)?;
            assert!(
                result.is_err(),
                "altered terminal-stamp byte {byte} must refuse submission"
            );
            let request = namespace
                .recover_retired(backend.clone(), desired.clone())
                .await?;
            let changed = Arc::new(ChangedStampAfterBinding {
                backend: backend.clone(),
                pin_dir: pin_dir.clone(),
                byte,
                entered: AtomicUsize::new(0),
            });
            let result = namespace
                .send_n3_end_markers(changed.clone(), request)
                .await;
            assert_eq!(changed.entered.load(Ordering::SeqCst), 1);
            assert!(
                matches!(
                    result,
                    Err(opc_gtpu_dataplane::GtpuN3EndMarkerError::Backend)
                ),
                "post-binding terminal-stamp byte {byte} must refuse submission"
            );
        }
        expect_no_datagram(&peer);
        // Restore live or foreign-owned rows after retirement. The original
        // selector keys must be absent even when their values point elsewhere;
        // enumerating only references to the retired group is insufficient.
        macro_rules! refuse_resurrected {
            ($name:expr, $key_len:expr, $value_len:expr, $rows:expr) => {{
                let map = Map::from_map_data(MapData::from_pin(pin_dir.join($name))?)?;
                let mut map = BpfHashMap::<_, [u8; $key_len], [u8; $value_len]>::try_from(map)?;
                for (key, value) in $rows {
                    let request = namespace
                        .recover_retired(backend.clone(), desired.clone())
                        .await?;
                    map.insert(key, value, 0)?;
                    let result = namespace
                        .send_n3_end_markers(backend.clone(), request)
                        .await;
                    map.remove(&key)?;
                    assert!(
                        matches!(
                            result,
                            Err(opc_gtpu_dataplane::GtpuN3EndMarkerError::Backend)
                        ),
                        "resurrected {} must refuse End Markers",
                        $name
                    );
                }
            }};
        }
        refuse_resurrected!(
            MAP_SESSION_GROUPS,
            GTPU_SESSION_GROUP_ID_LEN,
            GTPU_SESSION_GROUP_VALUE_LEN,
            active_graph
        );
        refuse_resurrected!(
            MAP_SESSION_TRANSACTIONS,
            GTPU_SESSION_GROUP_ID_LEN,
            GTPU_SESSION_TRANSACTION_VALUE_LEN,
            [(
                desired.id().to_bytes(),
                [0; GTPU_SESSION_TRANSACTION_VALUE_LEN]
            )]
        );
        for foreign in [false, true] {
            let reassign = |value: [u8; GTPU_SESSION_GROUP_REF_LEN]| {
                if !foreign {
                    return value;
                }
                let reference = GtpuSessionGroupRef::decode(&value).unwrap();
                GtpuSessionGroupRef::new(
                    GtpuSessionGroupId::new([0x55; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
                    reference.base(),
                    reference.desired(),
                )
                .unwrap()
                .encode()
            };
            refuse_resurrected!(
                MAP_SESSION_UPLINK_INDEX,
                GTPU_SESSION_UPLINK_KEY_LEN,
                GTPU_SESSION_GROUP_REF_LEN,
                active_uplink
                    .iter()
                    .map(|(key, value)| (*key, reassign(*value)))
            );
            refuse_resurrected!(
                MAP_SESSION_DOWNLINK_INDEX,
                GTPU_SESSION_DOWNLINK_KEY_LEN,
                GTPU_SESSION_GROUP_REF_LEN,
                active_downlink
                    .iter()
                    .map(|(key, value)| (*key, reassign(*value)))
            );
        }
        expect_no_datagram(&peer);
        let retired = completion.into_retired_claim();
        let repeated = namespace
            .send_n3_end_markers(backend.clone(), retired)
            .await?;
        assert_eq!(repeated.datagram_count(), count);
        for _ in 0..count {
            assert!(expected_markers.contains(&receive(&peer)));
        }
        drop(repeated);
        drop(namespace);
        drop(backend);
        drop(net);
    }
    eprintln!("OPC_GTPU_N3_END_MARKER_PROVEN: retired dual-family traffic, exact terminal stamp and selector absence, backend adoption, shared control queue, original IPv4 tunnel tuple and ordered one/two-marker submission");
    Ok(())
}
