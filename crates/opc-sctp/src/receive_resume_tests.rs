//! Synthetic syscall sequences exercise the production receive owner. These
//! are independent boundary schedules, not captured traffic or SCTP wire frames.
use super::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

struct Chunk {
    received: opc_libsctp_sys::Received,
    bytes: Vec<u8>,
}
fn data(bytes: &[u8], end: bool) -> Chunk {
    Chunk {
        received: opc_libsctp_sys::Received {
            bytes: bytes.len(),
            info: Some(opc_libsctp_sys::RecvInfo {
                stream_id: 3,
                ssn: 7,
                flags: 0,
                ppid_network_order: NGAP_PPID.to_network_order(),
                tsn: 10,
                cumulative_tsn: 9,
                context: 0,
                assoc_id: 11,
            }),
            flags: opc_libsctp_sys::RecvFlags {
                notification: false,
                end_of_record: end,
                payload_truncated: false,
                control_truncated: false,
            },
        },
        bytes: bytes.to_vec(),
    }
}
fn notification() -> Chunk {
    let mut bytes = vec![];
    bytes.extend_from_slice(&opc_libsctp_sys::SCTP_SENDER_DRY_EVENT_NOTIFICATION.to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    bytes.extend_from_slice(&(SCTP_SENDER_DRY_EVENT_BYTES as u32).to_ne_bytes());
    bytes.extend_from_slice(&11i32.to_ne_bytes());
    let mut chunk = data(&bytes, true);
    chunk.received.info = None;
    chunk.received.flags.notification = true;
    chunk
}
struct Source {
    chunks: AsyncMutex<mpsc::UnboundedReceiver<Result<Chunk, ReceiveFailure>>>,
}
impl ReceiveChunkSource for Source {
    #[allow(
        clippy::manual_async_fn,
        reason = "matches the production source's Send future contract"
    )]
    fn recv_chunk<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = Result<opc_libsctp_sys::Received, ReceiveFailure>> + Send + 'a {
        async move {
            let chunk = self
                .chunks
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| ReceiveFailure::close_socket(SctpError::Closed))??;
            assert!(chunk.bytes.len() <= buffer.len(), "bounded synthetic chunk");
            buffer[..chunk.bytes.len()].copy_from_slice(&chunk.bytes);
            Ok(chunk.received)
        }
    }
}
fn source() -> (mpsc::UnboundedSender<Result<Chunk, ReceiveFailure>>, Source) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (
        sender,
        Source {
            chunks: AsyncMutex::new(receiver),
        },
    )
}
fn send(sender: &mpsc::UnboundedSender<Result<Chunk, ReceiveFailure>>, chunk: Chunk) {
    assert!(
        sender.send(Ok(chunk)).is_ok(),
        "synthetic source remains open"
    );
}
fn pending<F: Future>(future: Pin<&mut F>) {
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        future.poll(&mut context).is_pending(),
        "receive reaches the controlled wait"
    );
}
fn complete(message: InboundMessage, bytes: &[u8]) {
    assert!(
        message.payload.as_ref() == bytes,
        "complete record must retain every consumed byte"
    );
    assert!(!message.notification && !message.truncated && !message.control_truncated);
    assert!(message.stream_id == 3 && message.assoc_id == 11 && message.ppid == NGAP_PPID);
}

#[tokio::test]
async fn cancellation_preserves_every_prefix_and_next_record() {
    for split in 1..9 {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        let bytes = b"123456789";
        send(&sender, data(&bytes[..split], false));
        let mut first = Box::pin(owner.recv(&source, bytes.len()));
        pending(first.as_mut());
        drop(first);
        send(&sender, data(&bytes[split..], true));
        complete(owner.recv(&source, bytes.len()).await.unwrap(), bytes);
        send(&sender, data(b"next", true));
        complete(owner.recv(&source, bytes.len()).await.unwrap(), b"next");
    }
}

#[tokio::test]
async fn notifications_preserve_partial_data_and_the_data_bound() {
    let owner = ReceiveOwner::new();
    let (sender, source) = source();
    send(&sender, data(b"a", false));
    for _ in 0..3 {
        send(&sender, notification());
        let event = owner.recv(&source, 2).await.unwrap();
        assert!(event.notification);
        assert!(matches!(
            event.event,
            Some(SctpEvent::SenderDry { assoc_id: 11 })
        ));
    }
    send(&sender, data(b"b", true));
    complete(owner.recv(&source, 2).await.unwrap(), b"ab");
}

#[tokio::test]
async fn queued_receiver_resumes_the_cancelled_owner_record() {
    let owner = ReceiveOwner::new();
    let (sender, source) = source();
    send(&sender, data(b"start", false));
    let mut first = Box::pin(owner.recv(&source, 9));
    pending(first.as_mut());
    let mut second = Box::pin(owner.recv(&source, 9));
    pending(second.as_mut());
    drop(first);
    send(&sender, data(b"tail", true));
    complete(second.await.unwrap(), b"starttail");
}

#[tokio::test]
async fn repeated_cancellation_cannot_reset_the_byte_limit() {
    let owner = ReceiveOwner::new();
    let (sender, source) = source();
    for _ in 0..3 {
        send(&sender, data(b"ab", false));
        let mut receive = Box::pin(owner.recv(&source, 7));
        pending(receive.as_mut());
        drop(receive);
    }
    send(&sender, data(b"cd", true));
    let result = owner.recv(&source, 7).await;
    assert!(result.is_err(), "cumulative bound");
    let error = result.unwrap_err();
    assert!(error.close_socket);
    assert!(matches!(
        error.error,
        SctpError::MessageTooLarge {
            max_message_bytes: 7
        }
    ));
}

#[tokio::test]
async fn complete_chunk_metadata_cannot_splice_different_records() {
    for change in 0..5 {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        send(&sender, data(b"first", false));
        let mut last = data(b"last", true);
        let info = last.received.info.as_mut().unwrap();
        match change {
            0 => info.stream_id += 1,
            1 => info.assoc_id += 1,
            2 => info.ppid_network_order = PayloadProtocolIdentifier::new(66).to_network_order(),
            3 => info.ssn += 1,
            _ => info.flags |= opc_libsctp_sys::SCTP_UNORDERED_FLAG,
        }
        send(&sender, last);
        let result = owner.recv(&source, 9).await;
        assert!(result.is_err(), "different record metadata");
        let error = result.unwrap_err();
        assert!(error.close_socket);
        assert!(!format!("{:?}", error.error).contains("first"));
    }
}

#[tokio::test]
async fn ordered_tsn_progress_and_unordered_ssn_do_not_change_identity() {
    for unordered in [false, true] {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        let mut first = data(b"a", false);
        let mut last = data(b"b", true);
        let info = last.received.info.as_mut().unwrap();
        info.tsn += 1;
        info.cumulative_tsn += 1;
        if unordered {
            first.received.info.as_mut().unwrap().flags |= opc_libsctp_sys::SCTP_UNORDERED_FLAG;
            info.flags |= opc_libsctp_sys::SCTP_UNORDERED_FLAG;
            info.ssn += 1; // RFC 4960 6.6: unordered SSN has no significance.
        }
        send(&sender, first);
        send(&sender, last);
        let message = owner.recv(&source, 2).await.unwrap();
        assert!(message.payload.as_ref() == b"ab");
        assert!(
            message.order
                == if unordered {
                    DeliveryOrder::Unordered
                } else {
                    DeliveryOrder::Ordered
                }
        );
    }
}

#[tokio::test]
async fn close_cancellation_race_scrubs_partial_state_and_stays_terminal() {
    for close_while_polled in [false, true] {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        send(&sender, data(b"partial", false));
        let mut receive = Box::pin(owner.recv(&source, 20));
        pending(receive.as_mut());
        if close_while_polled {
            owner.close();
            assert!(
                owner.lock_state().accumulator.is_none(),
                "close clears state before cancellation"
            );
        }
        drop(receive);
        if !close_while_polled {
            owner.close();
        }
        {
            assert!(owner.lock_state().accumulator.is_none());
            assert!(owner.scratch.lock().await.is_zeroed());
        }
        send(&sender, data(b"tail", true));
        assert!(matches!(
            owner.recv(&source, 20).await,
            Err(ReceiveFailure {
                error: SctpError::Closed,
                ..
            })
        ));
        assert!(
            source.chunks.lock().await.try_recv().is_ok(),
            "closed owner cannot consume another record"
        );
    }
}

fn lifecycle(association: bool, assoc_id: i32) -> Chunk {
    let mut bytes = vec![];
    if association {
        bytes.extend_from_slice(&opc_libsctp_sys::SCTP_ASSOC_CHANGE_NOTIFICATION.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&20u32.to_ne_bytes());
        bytes.extend_from_slice(&2u16.to_ne_bytes()); // Linux SCTP_RESTART.
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&4u16.to_ne_bytes());
        bytes.extend_from_slice(&4u16.to_ne_bytes());
    } else {
        bytes.extend_from_slice(&opc_libsctp_sys::SCTP_SHUTDOWN_EVENT_NOTIFICATION.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&12u32.to_ne_bytes());
    }
    bytes.extend_from_slice(&assoc_id.to_ne_bytes());
    let mut chunk = data(&bytes, true);
    chunk.received.info = None;
    chunk.received.flags.notification = true;
    chunk
}

#[tokio::test]
async fn lifecycle_invalidates_only_its_associations_partial_record() {
    for association in [false, true] {
        for same in [false, true] {
            let owner = ReceiveOwner::new();
            let (sender, source) = source();
            send(&sender, data(b"old", false));
            send(&sender, lifecycle(association, if same { 11 } else { 12 }));
            let event = owner.recv(&source, 7).await.unwrap();
            assert!(event.notification);
            assert!(matches!(
                event.event,
                Some(SctpEvent::AssociationChange { .. } | SctpEvent::Shutdown { .. })
            ));
            send(&sender, data(b"next", true));
            complete(
                owner.recv(&source, 7).await.unwrap(),
                if same { b"next" } else { b"oldnext" },
            );
        }
    }
}

#[tokio::test]
async fn unknown_transition_and_changed_partial_bound_fail_closed() {
    for unknown_event in [false, true] {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        send(&sender, data(b"old", false));
        let mut first = Box::pin(owner.recv(&source, 7));
        pending(first.as_mut());
        drop(first);
        let cap = if unknown_event {
            let mut event = notification();
            event.bytes[..2].copy_from_slice(&0xffffu16.to_ne_bytes());
            send(&sender, event);
            7
        } else {
            // A missing bound guard must produce a wrong result, not wait for
            // an unfulfilled synthetic source in the mutation detector.
            send(&sender, data(b"next", true));
            8
        };
        let result = owner.recv(&source, cap).await;
        assert!(result.is_err(), "unknown record boundary must reject");
        assert!(result.unwrap_err().close_socket);
        assert!(owner.lock_state().accumulator.is_none());
    }
}

#[tokio::test]
async fn recoverable_readiness_error_keeps_prefix_and_terminal_error_discards_it() {
    for terminal in [false, true] {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        send(&sender, data(b"old", false));
        let error = io_err("synthetic_receive", io::ErrorKind::Interrupted.into());
        let failure = if terminal {
            ReceiveFailure::close_socket(error)
        } else {
            ReceiveFailure::preserve_socket(error)
        };
        assert!(sender.send(Err(failure)).is_ok());
        let result = owner.recv(&source, 7).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().close_socket, terminal);
        assert!(owner.scratch.lock().await.is_zeroed());
        send(&sender, data(b"next", true));
        if terminal {
            assert!(owner.lock_state().accumulator.is_none());
            assert!(matches!(
                owner.recv(&source, 7).await,
                Err(ReceiveFailure {
                    error: SctpError::Closed,
                    ..
                })
            ));
            assert!(source.chunks.lock().await.try_recv().is_ok());
        } else {
            complete(owner.recv(&source, 7).await.unwrap(), b"oldnext");
        }
    }
}

#[tokio::test]
async fn partial_record_rejects_incomplete_notification_boundaries() {
    for change in 0..5 {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        send(&sender, data(b"old", false));
        let mut event = notification();
        match change {
            0 => event.received.flags.end_of_record = false,
            1 => event.received.flags.payload_truncated = true,
            2 => event.received.flags.control_truncated = true,
            3 => event.bytes[4..8].copy_from_slice(&11u32.to_ne_bytes()),
            _ => {
                event.bytes.push(0);
                event.received.bytes += 1;
            }
        }
        send(&sender, event);
        let result = owner.recv(&source, 7).await;
        assert!(
            result.is_err(),
            "incomplete event cannot attest a record boundary"
        );
        assert!(result.unwrap_err().close_socket);
        assert!(owner.lock_state().accumulator.is_none());
        assert!(owner.scratch.lock().await.is_zeroed());
    }
}

#[tokio::test]
async fn ancillary_presence_cannot_change_without_truncation_evidence() {
    for missing_first in [false, true] {
        let owner = ReceiveOwner::new();
        let (sender, source) = source();
        let mut first = data(b"a", false);
        let mut last = data(b"b", true);
        if missing_first {
            first.received.info = None;
        } else {
            last.received.info = None;
        }
        send(&sender, first);
        send(&sender, last);
        let result = owner.recv(&source, 2).await;
        assert!(result.is_err(), "ancillary identity is incomplete");
        assert!(result.unwrap_err().close_socket);
    }
}
