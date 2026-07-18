//! Privileged Linux-kernel evidence for exact single-SA relocation.
//!
//! Run this ignored test inside a fresh network namespace. Before installing a
//! fixture, the backend sends the upstream missing-SA capability probe with a
//! distinct non-zero SPI. `EINVAL` (message unknown) and `ENOPROTOOPT` (feature
//! disabled) prove the missing path; `ESRCH` proves support. Only the supported
//! branch installs and relocates an SA, and any later real-operation `EINVAL`
//! remains a test failure.

#![cfg(target_os = "linux")]

use std::env;

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    LinuxXfrmBackend, QuerySaRequest, RelocateSaRequest, RemoveSaRequest, SaParameters,
    SaRelocationDirection, SaRelocationEncap, UdpEncap, XfrmBackend, XfrmCapability, XfrmError,
    XfrmId, XfrmMode, XfrmRequestId, XfrmSelector,
};

const IPPROTO_ESP: u8 = 50;
const SPI: u32 = 0x3150_0001;

fn ipv4(octets: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(octets)
}

fn parameters() -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(ipv4([10, 31, 5, 1]), ipv4([10, 31, 5, 2]), 17),
        id: XfrmId {
            destination: ipv4([192, 0, 2, 20]),
            spi: SPI,
            protocol: IPPROTO_ESP,
        },
        source_address: ipv4([192, 0, 2, 10]),
        request_id: XfrmRequestId::new(315),
        auth: Some((
            AuthAlgorithm::hmac_sha256(96),
            KeyMaterial::new(vec![0x31; 32]),
        )),
        crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0x50; 16]))),
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
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, XFRM, and a fresh network namespace"]
async fn capability_probe_precedes_and_gates_exact_sa_relocation_proof(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_XFRM_RUN_RELOCATION_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping: set OPC_XFRM_RUN_RELOCATION_PRIVILEGED=1 inside a fresh privileged netns"
        );
        return Ok(());
    }

    let backend = LinuxXfrmBackend::new();
    match backend.sa_relocation_capability().await? {
        XfrmCapability::Available => {}
        XfrmCapability::Missing => {
            assert_eq!(
                backend.sa_relocation_capability().await?,
                XfrmCapability::Missing
            );
            return Ok(());
        }
        capability => {
            return Err(std::io::Error::other(format!(
                "unexpected relocation capability: {capability:?}"
            ))
            .into());
        }
    }

    let parameters = parameters();
    backend
        .install_sa(InstallSaRequest {
            parameters: parameters.clone(),
        })
        .await?;
    let old_query = QuerySaRequest::new(
        parameters.id.destination,
        parameters.id.protocol,
        parameters.id.spi,
    );
    let current = backend.query_sa_relocation_identity(old_query).await?;
    let request = RelocateSaRequest {
        current,
        new_source_address: ipv4([198, 51, 100, 10]),
        new_destination: ipv4([198, 51, 100, 20]),
        encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
        direction: SaRelocationDirection::Inbound,
    };
    let new_query = QuerySaRequest::new(
        request.new_destination,
        parameters.id.protocol,
        parameters.id.spi,
    );

    match backend.relocate_sa(request.clone()).await {
        Ok(()) => {
            let relocated = backend.query_sa(new_query).await?;
            assert_eq!(relocated.id.destination, request.new_destination);
            assert_eq!(relocated.source_address, request.new_source_address);
            let relocated_identity = backend.query_sa_relocation_identity(new_query).await?;
            let mut expected_identity = request.current.clone();
            expected_identity.id.destination = request.new_destination;
            expected_identity.source_address = request.new_source_address;
            expected_identity.encap = Some(UdpEncap::esp_in_udp(4500, 62_000));
            assert_eq!(relocated_identity, expected_identity);
            assert!(matches!(
                backend.query_sa(old_query).await,
                Err(XfrmError::NotFound)
            ));
            assert_eq!(
                backend.sa_relocation_capability().await?,
                XfrmCapability::Available
            );
            backend
                .remove_sa(RemoveSaRequest::new(
                    request.new_destination,
                    parameters.id.protocol,
                    parameters.id.spi,
                ))
                .await?;
        }
        Err(error) => return Err(Box::<dyn std::error::Error>::from(error)),
    }
    Ok(())
}
