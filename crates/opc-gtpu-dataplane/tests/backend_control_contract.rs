use opc_gtpu_dataplane::{
    GtpDevice, GtpuDataplaneBackend, GtpuError, LinuxGtpuDataplaneBackend,
    MockGtpuDataplaneBackend, UnsupportedGtpuDataplaneBackend,
};

#[tokio::test]
async fn unqualified_backends_report_exact_control_port_unsupported() {
    let backends: Vec<Box<dyn GtpuDataplaneBackend>> = vec![
        Box::new(MockGtpuDataplaneBackend::new()),
        Box::new(LinuxGtpuDataplaneBackend::new()),
        Box::new(UnsupportedGtpuDataplaneBackend::new()),
    ];
    let device = GtpDevice {
        name: "sensitive-synthetic-device".into(),
        ifindex: 73,
    };
    for backend in backends {
        let error = backend.open_gtpu_control_port(&device).await.unwrap_err();
        assert!(matches!(
            error,
            GtpuError::UnsupportedFeature {
                feature: "gtpu_control_port"
            }
        ));
        assert!(!format!("{error:?} {error}").contains(&device.name));
    }
}

#[test]
fn external_consumer_fake_accepts_testkit_downlink_inputs() {
    use opc_gtpu_dataplane::{
        testkit, GtpAddressFamily, GtpBearerMark, GtpuDownlinkInjection,
        GtpuDownlinkInjectionCounters, GtpuDownlinkInjectionError, GtpuDownlinkInjectionPort,
    };

    #[derive(Debug, Default)]
    struct ConsumerFake {
        counters: GtpuDownlinkInjectionCounters,
    }

    impl GtpuDownlinkInjectionPort for ConsumerFake {
        fn inject(
            &mut self,
            outcome: GtpuDownlinkInjection<'_>,
        ) -> Result<usize, GtpuDownlinkInjectionError> {
            let count = match outcome {
                GtpuDownlinkInjection::Decapsulated(packet) => {
                    assert_eq!(packet.inner_packet(), b"synthetic unvalidated packet");
                    assert_eq!(packet.bearer_mark(), GtpBearerMark::new(37));
                    assert_eq!(packet.family(), GtpAddressFamily::Ipv4);
                    1
                }
                GtpuDownlinkInjection::Fragmented(batch) => {
                    assert_eq!(batch.bearer_mark(), None);
                    assert_eq!(batch.mtu(), 576);
                    assert_eq!(batch.fragments()[0].as_ref(), b"first synthetic piece");
                    assert_eq!(batch.fragments()[1].as_ref(), b"second synthetic piece");
                    batch.fragments().len()
                }
                _ => panic!("unexpected input contract"),
            };
            self.counters.packets_accepted += u64::try_from(count).unwrap();
            Ok(count)
        }

        fn counters(&self) -> GtpuDownlinkInjectionCounters {
            self.counters
        }
    }

    let packet = testkit::decapsulated_downlink(
        bytes::Bytes::from_static(b"synthetic unvalidated packet"),
        GtpBearerMark::new(37),
        GtpAddressFamily::Ipv4,
    );
    let batch = testkit::fragmented_downlink(
        vec![
            bytes::Bytes::from_static(b"first synthetic piece"),
            bytes::Bytes::from_static(b"second synthetic piece"),
        ],
        None,
        576,
    );
    let mut fake: Box<dyn GtpuDownlinkInjectionPort> = Box::<ConsumerFake>::default();
    assert_eq!(fake.inject((&packet).into()), Ok(1));
    assert_eq!(fake.inject((&batch).into()), Ok(2));
    assert_eq!(fake.counters().packets_accepted, 3);
    assert!(!format!("{fake:?} {packet:?} {batch:?}").contains("synthetic"));
}
