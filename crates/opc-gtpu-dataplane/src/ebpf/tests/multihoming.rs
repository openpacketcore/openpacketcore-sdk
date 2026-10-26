use super::*;
use crate::{GtpuPeerSourcePolicy, PdpContextMismatchField};

#[tokio::test]
async fn multihoming_policy_survives_restart_and_conflicts_with_strict_readback() {
    for ipv6 in [false, true] {
        for marked in [false, true] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = context();
            if ipv6 {
                desired.ms_address = IpAddr::V6("2001:db8:45:1::".parse().unwrap());
            }
            if marked {
                desired.bearer_mark = GtpBearerMark::new(7);
            }
            desired.downlink_peer_source_policy = GtpuPeerSourcePolicy::TeidAndLocal;
            assert_eq!(
                backend
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Installed
            );
            drop(backend);
            suspend_fake_attachment(&mut runtime.state(), S2BU_IFINDEX);
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime);
            restarted.resolve_device("s2bu").await.unwrap();
            for selector in [
                PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                ),
                PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(&desired).unwrap(),
                ),
            ] {
                assert_eq!(
                    restarted.read_pdp_context(selector).await.unwrap(),
                    PdpContextReadback::Present(desired.clone())
                );
            }
            let mut strict = desired.clone();
            strict.downlink_peer_source_policy = GtpuPeerSourcePolicy::BackendDefault;
            let PdpContextInstallOutcome::Conflict(conflict) = restarted
                .install_pdp_context_classified(strict.clone())
                .await
                .unwrap()
            else {
                panic!("different peer policy must conflict");
            };
            assert_eq!(
                conflict.mismatches(),
                &[PdpContextMismatchField::DownlinkPeerSourcePolicy]
            );
            assert!(matches!(
                restarted.remove_pdp_context_exact(strict).await.unwrap(),
                PdpContextRemovalOutcome::Conflict(_)
            ));
            assert_eq!(
                restarted
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::ExactAlreadyPresent
            );
            assert_eq!(
                restarted.remove_pdp_context_exact(desired).await.unwrap(),
                PdpContextRemovalOutcome::Removed
            );
        }
    }
}

#[test]
fn multihoming_grouped_and_n3_readback_retain_policy_for_both_families() {
    for n3 in [false, true] {
        let entries = [grouped_v4_entry(1, 2), grouped_v6_entry(3, 4, ipv6_peer())]
            .into_iter()
            .map(|entry| {
                let entry = entry.with_peer_source_policy(GtpuPeerSourcePolicy::TeidAndLocal);
                if n3 {
                    entry.restore_n3_qfi(9).unwrap()
                } else {
                    entry
                }
            })
            .collect();
        let group = grouped_group(7, GtpuSessionDeviceId::new([8; 16]).unwrap(), entries);
        let record = grouped_record_from_model(&group, GtpuSessionGeneration::INITIAL).unwrap();
        let retained = GtpuSessionGroupRecord::decode(&record.encode()).unwrap();
        let device = GtpDevice {
            name: "s2bu".to_owned(),
            ifindex: S2BU_IFINDEX,
        };
        assert_eq!(grouped_model_from_record(retained, &device), Some(group));
    }
}
