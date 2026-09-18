use super::*;
use crate::{OutboundMessage, SctpAssociation, SctpEndpoint, SctpEndpointConfig, NGAP_PPID};
use std::task::{Context, Poll, Waker};

const GUARD: Duration = Duration::from_secs(5);

fn bounds() -> N2ReconnectPolicy {
    N2ReconnectPolicy::new(2, GUARD, GUARD, Duration::ZERO).unwrap()
}

async fn connected(
    owner: &N2AssociationOwner,
    endpoint: &SctpEndpoint,
) -> (N2Candidate, SctpAssociation) {
    let address = endpoint.local_addresses().unwrap()[0];
    let candidate = owner
        .connect_candidate(SctpConnectConfig::new(address), bounds())
        .await
        .unwrap();
    let accepted = tokio::time::timeout(GUARD, endpoint.accept())
        .await
        .expect("native accept timed out")
        .unwrap();
    (candidate, accepted)
}

async fn payload(owner: &N2AssociationOwner, generation: &N2Generation) -> N2Received {
    tokio::time::timeout(GUARD, async {
        for _ in 0..32 {
            let received = owner.recv(generation).await.unwrap();
            assert!(
                !received.retired(),
                "unexpected native generation retirement"
            );
            if matches!(received.inbound(), N2Inbound::Payload(_)) {
                return received;
            }
        }
        panic!("native event count exceeded test bound");
    })
    .await
    .expect("native owner DATA timed out")
}

async fn peer_closed(peer: &SctpAssociation) {
    tokio::time::timeout(GUARD, async {
        for _ in 0..32 {
            match peer.recv().await {
                Err(_) => return,
                Ok(message) if message.notification => {}
                Ok(_) => panic!("unexpected DATA on a retired native connection"),
            }
        }
        panic!("native peer remained open");
    })
    .await
    .expect("native peer closure timed out");
}

#[tokio::test]
#[ignore = "requires Linux SCTP; explicitly executed by required CI"]
async fn native_generation_replacement_reconnect_and_shutdown() {
    for reverse in [false, true] {
        let endpoint = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .unwrap();
        let owner = N2AssociationOwner::new();
        let (a, pa) = connected(&owner, &endpoint).await;
        let (b, pb) = connected(&owner, &endpoint).await;
        let (winner, loser, peer, losing_peer) = if reverse {
            (b, a, pb, pa)
        } else {
            (a, b, pa, pb)
        };
        assert!(format!("{winner:?}") == "N2Candidate { .. }");
        let generation = owner.promote(winner).unwrap();
        assert!(format!("{generation:?}") == "N2Generation { .. }");
        assert!(matches!(
            owner.promote(loser),
            Err(N2Error::CandidateSuperseded)
        ));
        peer_closed(&losing_peer).await;
        let readback = owner.readback(&generation).unwrap();
        assert!(readback.local_addresses() == peer.peer_addresses().unwrap());
        assert!(readback.peer_addresses() == peer.local_addresses().unwrap());
        assert!(
            readback.peer_path_health().len() == 1 && readback.generation() == generation.number()
        );

        // Read native notifications, then cancel the actual pending syscall
        // wait; following records must retain their stream and record order.
        let mut pending = Box::pin(owner.recv(&generation));
        for _ in 0..32 {
            match pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Pending => break,
                Poll::Ready(Ok(received)) => {
                    assert!(
                        matches!(received.inbound(), N2Inbound::Notification(_))
                            && !received.retired()
                    );
                    pending = Box::pin(owner.recv(&generation));
                }
                Poll::Ready(Err(_)) => panic!("native receive closed before cancellation"),
            }
        }
        assert!(pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(pending);
        for (stream, bytes) in [(3, b"one"), (2, b"two"), (3, b"end")] {
            peer.send(OutboundMessage::ordered(
                Bytes::from_static(bytes),
                stream,
                NGAP_PPID,
            ))
            .await
            .unwrap();
        }
        let mut stream3 = Vec::new();
        for _ in 0..3 {
            let received = payload(&owner, &generation).await;
            assert!(received.generation() == generation.number());
            let N2Inbound::Payload(pdu) = received.into_inbound() else {
                unreachable!()
            };
            if pdu.stream_id() == 3 {
                stream3.push(pdu.into_payload());
            } else {
                assert!(pdu.stream_id() == 2 && pdu.payload().as_ref() == b"two");
            }
        }
        assert!(stream3 == [Bytes::from_static(b"one"), Bytes::from_static(b"end")]);

        let mut pending = Box::pin(owner.recv(&generation));
        assert!(pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (new, new_peer) = connected(&owner, &endpoint).await;
        let new_generation = owner.promote(new).unwrap();
        assert!(matches!(pending.await, Err(N2Error::GenerationRetired)));
        assert!(matches!(
            owner.readback(&generation),
            Err(N2Error::GenerationRetired)
        ));
        assert!(
            owner.send(&generation, Bytes::from_static(b"old"), 3).await
                == Err(N2Error::GenerationRetired)
        );
        assert!(owner.retire(&generation) == Err(N2Error::GenerationRetired));
        drop(generation);
        peer_closed(&peer).await;
        assert!(owner.readback(&new_generation).is_ok());

        // The peer closes a live kernel association; the typed terminal event
        // must retire its generation before any queued application DATA.
        new_peer.abort_handle().abort();
        tokio::time::timeout(GUARD, async {
            for _ in 0..32 {
                let result = owner.recv(&new_generation).await;
                let received = result.expect("kernel did not deliver a typed close event");
                if received.retired() {
                    assert!(matches!(
                        received.inbound(),
                        N2Inbound::Notification(
                            SctpEvent::Shutdown { .. } | SctpEvent::AssociationChange { .. }
                        )
                    ));
                    assert!(matches!(
                        owner.readback(&new_generation),
                        Err(N2Error::GenerationRetired)
                    ));
                    return;
                }
            }
            panic!("native shutdown event bound exceeded");
        })
        .await
        .expect("native terminal event timed out");

        // A post-shutdown connection gets a new token; a dropped candidate
        // and a dropped current token each close their actual peer socket.
        let (discard, discard_peer) = connected(&owner, &endpoint).await;
        drop(discard);
        peer_closed(&discard_peer).await;
        let (last, last_peer) = connected(&owner, &endpoint).await;
        let last = owner.promote(last).unwrap();
        assert!(last.number() > new_generation.number());
        drop(last);
        peer_closed(&last_peer).await;
        owner.close();
        assert!(matches!(
            owner
                .connect_candidate(
                    SctpConnectConfig::new(endpoint.local_addresses().unwrap()[0]),
                    bounds()
                )
                .await,
            Err(N2Error::OwnerClosed)
        ));
    }
    println!("native N2 generation lifecycle assertions completed");
}
