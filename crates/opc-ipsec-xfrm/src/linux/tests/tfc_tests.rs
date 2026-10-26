//! TFC intent must survive exact reads and acknowledged in-place updates.
use super::*;

fn tfc_readback(parameters: &SaParameters, attribute: Option<&[u8]>) -> SensitiveBuffer {
    let mut unpadded = parameters.clone();
    unpadded.tfc_pad = None;
    let mut body = encode_sa_binding_readback(&unpadded);
    if let Some(attribute) = attribute {
        append_attr(&mut body, XFRMA_TFCPAD, attribute).unwrap();
    }
    body
}

#[test]
fn tfc_encoding_keeps_secret_buffer_allocation_for_every_target() {
    let mut parameters = sa_parameters();
    let disabled = encode_sa_info(&parameters).unwrap();
    assert!(route_attr_payload(&disabled, XFRMA_TFCPAD).is_none());
    for target in [1_u32, 1280, u32::MAX] {
        parameters.tfc_pad = Some(target);
        let mut allocations = Vec::new();
        let encoded =
            encode_sa_info_inner_observed(&parameters, false, None, |_, pointer, capacity| {
                allocations.push((pointer, capacity));
            })
            .unwrap();
        assert_eq!(XFRMA_TFCPAD, 22);
        assert_eq!(
            route_attr_payload(&encoded, XFRMA_TFCPAD),
            Some(target.to_ne_bytes().as_slice())
        );
        assert_eq!(encoded.len(), disabled.len() + 8);
        assert_eq!(allocations.len(), 2);
        assert_eq!(allocations[0], allocations[1]);
    }
}

#[test]
fn tfc_binding_checks_presence_and_value_in_both_directions() {
    for desired in [None, Some(1280)] {
        let mut request = outbound_binding_request();
        request.sa.parameters.tfc_pad = desired;
        let expectation = validate_outbound_request(&request).unwrap();
        for observed in [None, Some(1200_u32), Some(1280_u32)] {
            let attribute = observed.map(u32::to_ne_bytes);
            let body = tfc_readback(
                &request.sa.parameters,
                attribute.as_ref().map(|value| value.as_slice()),
            );
            assert_eq!(
                parse_outbound_sa_binding_snapshot(
                    &body,
                    &expectation,
                    Some(&request.sa.parameters)
                )
                .is_ok(),
                desired == observed,
                "desired={desired:?}, observed={observed:?}"
            );
        }
    }
}

#[test]
fn tfc_readback_rejects_noncanonical_wire_configuration() {
    let parameters = sa_parameters();
    for attribute in [vec![], vec![1, 2, 3], vec![0; 4], vec![0; 5]] {
        assert!(parse_sa_state(&tfc_readback(&parameters, Some(&attribute)), None).is_err());
    }
    let body = tfc_readback(&parameters, Some(&1280_u32.to_ne_bytes()));
    assert_eq!(parse_sa_state(&body, None).unwrap().tfc_pad, Some(1280));
    for (offset, value) in [(76, 51), (214, encode_mode(XfrmMode::Transport))] {
        let mut changed = body.clone();
        changed[offset] = value;
        assert!(parse_sa_state(&changed, None).is_err());
    }
    let mut duplicate = body;
    append_attr(&mut duplicate, XFRMA_TFCPAD, &1280_u32.to_ne_bytes()).unwrap();
    assert!(parse_sa_state(&duplicate, None).is_err());
}

#[tokio::test]
async fn tfc_rekey_ack_cannot_claim_an_ignored_configuration_change() {
    for (stored, desired) in [
        (None, Some(1280)),
        (Some(1280), None),
        (Some(1280), Some(1400)),
    ] {
        let mut parameters = sa_parameters();
        parameters.tfc_pad = stored;
        let observed = encode_sa_info(&parameters).unwrap();
        let transport = ScriptedTransport::new(vec![Ok(None), Ok(Some(observed.to_vec()))]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        parameters.tfc_pad = desired;
        assert!(
            matches!(
                backend.rekey_sa(RekeySaRequest { parameters }).await,
                Err(XfrmError::StateIndeterminate {
                    operation: "rekey_sa_tfc_readback"
                })
            ),
            "stored={stored:?}, desired={desired:?}"
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_UPDSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
    }
}

#[tokio::test]
async fn tfc_rekey_requires_matching_readback_including_absence() {
    for target in [None, Some(1280)] {
        let mut parameters = sa_parameters();
        parameters.tfc_pad = target;
        let observed = encode_sa_info(&parameters).unwrap();
        let transport = ScriptedTransport::new(vec![Ok(None), Ok(Some(observed.to_vec()))]);
        LinuxXfrmBackend::with_transport(transport.clone())
            .rekey_sa(RekeySaRequest {
                parameters: parameters.clone(),
            })
            .await
            .unwrap();
        assert_eq!(transport.requests().len(), 2);
        let transport = ScriptedTransport::new(vec![Ok(None), Err(XfrmError::NotFound)]);
        assert!(matches!(
            LinuxXfrmBackend::with_transport(transport)
                .rekey_sa(RekeySaRequest { parameters })
                .await,
            Err(XfrmError::StateIndeterminate {
                operation: "rekey_sa_tfc_readback"
            })
        ));
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and private netns"]
fn native_tfc_install_readback_and_ignored_update_are_reported_exactly() {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let backend = LinuxXfrmBackend::new();
            let mut parameters = sa_parameters();
            parameters.tfc_pad = Some(1280);
            backend
                .install_sa(InstallSaRequest {
                    parameters: parameters.clone(),
                })
                .await
                .unwrap();
            let query = QuerySaRequest {
                destination: parameters.id.destination,
                spi: parameters.id.spi,
                protocol: parameters.id.protocol,
                mark: parameters.mark,
            };
            assert_eq!(
                backend.query_sa(query.clone()).await.unwrap().tfc_pad,
                Some(1280)
            );
            backend
                .rekey_sa(RekeySaRequest {
                    parameters: parameters.clone(),
                })
                .await
                .unwrap();
            for target in [Some(1400), None] {
                parameters.tfc_pad = target;
                assert!(matches!(
                    backend
                        .rekey_sa(RekeySaRequest {
                            parameters: parameters.clone()
                        })
                        .await,
                    Err(XfrmError::StateIndeterminate {
                        operation: "rekey_sa_tfc_readback"
                    })
                ));
                assert_eq!(
                    backend.query_sa(query.clone()).await.unwrap().tfc_pad,
                    Some(1280)
                );
            }
            backend
                .remove_sa(RemoveSaRequest {
                    destination: parameters.id.destination,
                    spi: parameters.id.spi,
                    protocol: parameters.id.protocol,
                    mark: parameters.mark,
                })
                .await
                .unwrap();
            assert!(matches!(
                backend.query_sa(query).await,
                Err(XfrmError::NotFound)
            ));
        });
}
