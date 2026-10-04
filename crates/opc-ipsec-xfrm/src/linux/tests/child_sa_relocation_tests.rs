use super::*;
use crate::child_sa_relocation::{Program, Step};
use crate::child_sa_relocation_flow::{tests::intent, RelocationIo};

fn keyed_body(parameters: &SaParameters, direction: XfrmDirection) -> Vec<u8> {
    let mut body = encode_sa_binding_readback(parameters);
    if direction == XfrmDirection::In {
        remove_route_attr(&mut body, XFRM_USER_SA_INFO_LEN, XFRMA_SA_DIR);
        append_attr(&mut body, XFRMA_SA_DIR, &[XFRM_SA_DIR_IN]).unwrap();
    }
    body.to_vec()
}

fn responses(program: &Program, cut: usize) -> Vec<Result<Option<Vec<u8>>, XfrmError>> {
    let mut moved = vec![false; program.sas.len()];
    let mut policies: Vec<_> = program.policies.iter().map(|p| p.old.clone()).collect();
    for step in &program.steps[..cut] {
        match *step {
            Step::Sa(index) => moved[index] = true,
            Step::Policy { index, phase: 1 } => {
                policies[index] = program.policies[index].block.clone().unwrap()
            }
            Step::Policy { index, .. } => policies[index] = program.policies[index].new.clone(),
        }
    }
    let mut replies = Vec::new();
    for (index, resource) in program.sas.iter().enumerate() {
        let sa = if moved[index] {
            &resource.new
        } else {
            &resource.old
        };
        let identity = Ok(Some(encode_sa_info(sa).unwrap().to_vec()));
        let absent = Err(XfrmError::NotFound);
        if moved[index] {
            replies.extend([absent, identity]);
        } else {
            replies.extend([identity, absent]);
        }
        replies.push(Ok(Some(keyed_body(sa, resource.policy.direction))));
    }
    replies.extend(
        policies
            .iter()
            .map(|p| Ok(Some(encode_policy_info(p).unwrap().to_vec()))),
    );
    replies
}

#[tokio::test]
async fn every_individual_linux_query_failure_refuses_every_roster_prefix() {
    let mut failures = 0;
    for udp in [false, true] {
        let program = intent(udp).program().unwrap();
        for cut in 0..=17 {
            let replies = responses(&program, cut);
            assert_eq!(replies.len(), 30); // 8 * (old identity + target identity + keys) + 6 policies.
            let transport = ScriptedTransport::new(responses(&program, cut));
            let observed = transport.clone();
            let backend = LinuxXfrmBackend::with_transport(transport);
            assert_eq!(program.prefix(&backend).await.unwrap(), cut);
            assert_eq!(observed.requests().len(), 30);
            for query in 0..30 {
                for error in [
                    XfrmError::Unavailable,
                    XfrmError::io(
                        "detector_query",
                        io::Error::from(io::ErrorKind::PermissionDenied),
                    ),
                    XfrmError::StateIndeterminate {
                        operation: "detector_query",
                    },
                ] {
                    let mut replies = responses(&program, cut);
                    replies[query] = Err(error);
                    let transport = ScriptedTransport::new(replies);
                    let observed = transport.clone();
                    let backend = LinuxXfrmBackend::with_transport(transport);
                    assert!(
                        program.prefix(&backend).await.is_err(),
                        "udp={udp} cut={cut} query={query}"
                    );
                    assert!(observed.requests().iter().all(|r| matches!(
                        netlink_message_type(r),
                        XFRM_MSG_GETSA | XFRM_MSG_GETPOLICY
                    )));
                    failures += 1;
                }
            }
        }
    }
    assert_eq!(failures, 3240);
}

#[tokio::test]
async fn relocation_readback_requires_exact_keys_direction_and_unique_target_for_every_sa() {
    let program = intent(true).program().unwrap();
    for (index, resource) in program.sas.iter().enumerate() {
        for moved in [false, true] {
            for defect in ["keys", "direction", "missing-keys", "duplicate-target"] {
                let sa = if moved { &resource.new } else { &resource.old };
                let identity = Ok(Some(encode_sa_info(sa).unwrap().to_vec()));
                let absent = Err(XfrmError::NotFound);
                let mut replies = if moved {
                    vec![absent, identity]
                } else {
                    vec![identity, absent]
                };
                let mut altered = sa.clone();
                if defect == "keys" {
                    altered.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0xa7; 32]);
                }
                let direction = match (defect, resource.policy.direction) {
                    ("direction", XfrmDirection::In) => XfrmDirection::Out,
                    ("direction", _) => XfrmDirection::In,
                    (_, direction) => direction,
                };
                replies.push(if defect == "missing-keys" {
                    Err(XfrmError::NotFound)
                } else {
                    Ok(Some(keyed_body(&altered, direction)))
                });
                if defect == "duplicate-target" {
                    replies[usize::from(!moved)] = Ok(Some(
                        encode_sa_info(if moved { &resource.old } else { &resource.new })
                            .unwrap()
                            .to_vec(),
                    ));
                }
                let backend = LinuxXfrmBackend::with_transport(ScriptedTransport::new(replies));
                assert!(
                    backend.sa_is_new(resource).await.is_err(),
                    "sa={index} moved={moved} defect={defect}"
                );
            }
        }
    }
}
