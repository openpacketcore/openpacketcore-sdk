//! Live IPsec SA keymat mirroring for near-hitless failover without keys at
//! rest (experimental).
//!
//! An SA owner mirrors freshly derived key material to a designated standby
//! over mTLS; the standby holds it exclusively in zeroizing memory; on owner
//! loss it yields the keymat together with validated
//! [`opc_ipsec_lb::SameSpiResume`] evidence
//! ([`opc_ipsec_lb::ResumeKeySource::LiveMirrored`]) for the ordinary fenced
//! re-pin. See RFC 015 (`docs/rfc/015-live-sa-mirror.md`).
//!
//! The custody invariant is structural: this crate has no persistence
//! dependency, the keymat type is not serializable, key bytes live only in
//! [`zeroize::Zeroizing`] buffers, and the standby sink port is not a
//! session-store trait. The plane that persists never holds keys; the plane
//! that holds keys never persists.
//!
//! Yielding mirrored keymat does not grant ownership: split-brain protection
//! remains solely the re-pin fencer's job (`opc_ipsec_lb::OwnershipFencer`).

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod keymat;
pub mod mock;
pub mod ports;
pub mod server;
pub mod standby;
mod wire;

pub use client::{MirrorAddrResolver, RemoteMirrorProducer};
pub use error::SaMirrorError;
pub use keymat::{KeyEpoch, KeymatFormat, MirroredSaKeymat, SaCounterCheckpoint, SaMirrorInstall};
pub use mock::InProcessMirrorProducer;
pub use ports::{
    LiveMirroredTakeover, RepinTakeoverParams, SaMirrorProducer, SaMirrorSink, StandbyKeymatSource,
};
pub use server::{ReceiverHandle, SaMirrorReceiver};
pub use standby::{InMemoryStandbyHolder, DEFAULT_STANDBY_CAPACITY};

#[cfg(test)]
mod integration_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use opc_ipsec_lb::{
        ClusterNode, MockOwnershipFencer, MockOwnershipSource, MockRePinAuditSink,
        MockSteeringBackend, OwnershipFence, OwnershipTransitionId, RePinCoordinator, RePinRequest,
        ResumeKeySource, SaId, SendIvCounterMode, SendIvForwardJump, ShardId, SteerKey,
        SteeringRule, MIN_SEND_IV_FORWARD_JUMP,
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::wire::{
        read_frame, write_frame, MirrorRequest, MirrorResponse, CONTRACT_VERSION,
        DEFAULT_MAX_FRAME_SIZE,
    };

    fn install(sa: SaId, epoch: u64, bytes: &[u8]) -> SaMirrorInstall {
        SaMirrorInstall {
            sa,
            epoch: KeyEpoch::new(epoch).unwrap(),
            keymat: MirroredSaKeymat::new(
                KeymatFormat::new(7).unwrap(),
                Zeroizing::new(bytes.to_vec()),
            )
            .unwrap(),
            send_iv_next: 100,
            replay_highest_accepted: 20,
        }
    }

    fn esp_params() -> RepinTakeoverParams {
        RepinTakeoverParams {
            forward_jump: SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
            },
            max_reopened_packets: 64,
        }
    }

    #[tokio::test]
    async fn fake_mesh_takeover_is_accepted_by_the_fenced_repin_coordinator() {
        let sa = SaId::Esp { spi: 0x7788_99AA };
        let holder = Arc::new(InMemoryStandbyHolder::new());
        let producer = InProcessMirrorProducer::new(holder.clone());

        // Owner mirrors fresh keymat, then checkpoints counters.
        producer
            .mirror_install(install(sa, 1, &[0x5C; 36]))
            .await
            .unwrap();
        producer
            .mirror_checkpoint(SaCounterCheckpoint {
                sa,
                epoch: KeyEpoch::new(1).unwrap(),
                send_iv_next: 5_000,
                replay_highest_accepted: 4_800,
            })
            .await
            .unwrap();

        // Owner loss: the standby yields keymat plus validated evidence.
        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert_eq!(takeover.resume.key_source, ResumeKeySource::LiveMirrored);
        assert_eq!(takeover.resume.checkpointed_send_iv_next, 5_000);
        assert_eq!(takeover.keymat.expose_secret_bytes(), &[0x5C; 36]);

        // The evidence rides an ordinary fenced re-pin; the fencer stays the
        // only split-brain authority.
        let previous_owner = ClusterNode::new("worker-a");
        let new_owner = ClusterNode::new("worker-b");
        let fencer = MockOwnershipFencer::new();
        fencer.set_owner(sa, previous_owner.clone());
        let ownership = MockOwnershipSource::default();
        ownership.set_shard_owner(ShardId::new(2), new_owner.clone());
        let coordinator = RePinCoordinator::new(
            MockSteeringBackend::new(),
            fencer.clone(),
            ownership,
            MockRePinAuditSink::new(),
        );

        let outcome = coordinator
            .repin(RePinRequest {
                sa,
                transition_id: OwnershipTransitionId::new(1).unwrap(),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner,
                new_owner: new_owner.clone(),
                rule: SteeringRule {
                    shard: ShardId::new(1),
                    owner: ShardId::new(2),
                    key: SteerKey::EspSpi(0x7788_99AA),
                },
                resume: takeover.resume,
            })
            .await
            .unwrap();
        assert!(outcome.fence().get() > 1);
        assert_eq!(fencer.owner(sa), Some(new_owner));

        // Keymat is installed by the CNF adapter, then dropped => zeroized.
        drop(takeover);
        assert_eq!(holder.held_epoch(sa), None);
    }

    async fn drive_serve_stream(
        holder: Arc<InMemoryStandbyHolder>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<(), SaMirrorError>>,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);
            crate::server::serve_stream(
                holder.as_ref(),
                &mut reader,
                &mut writer,
                DEFAULT_MAX_FRAME_SIZE,
                Duration::from_secs(5),
            )
            .await
        });
        (client, server_task)
    }

    async fn hello<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        write_frame(
            stream,
            &MirrorRequest::Hello {
                contract_version: CONTRACT_VERSION,
                node_id: "test-producer".into(),
            },
            &[],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (ack, tail): (MirrorResponse, _) =
            read_frame(stream, DEFAULT_MAX_FRAME_SIZE).await.unwrap();
        assert_eq!(
            ack,
            MirrorResponse::HelloAck {
                contract_version: CONTRACT_VERSION
            }
        );
        assert!(tail.is_empty());
    }

    #[tokio::test]
    async fn served_stream_installs_checkpoints_and_withdraws_over_a_duplex_mesh() {
        let holder = Arc::new(InMemoryStandbyHolder::new());
        let (mut client, server_task) = drive_serve_stream(holder.clone()).await;
        hello(&mut client).await;

        let sa = SaId::Esp { spi: 42 };
        write_frame(
            &mut client,
            &MirrorRequest::Install {
                sa: sa.into(),
                epoch: 1,
                format: 7,
                send_iv_next: 100,
                replay_highest_accepted: 20,
            },
            &[0xEE; 32],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (response, _): (MirrorResponse, _) = read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(response, MirrorResponse::Accepted);

        // A stale-epoch install is an application-level rejection with a
        // redaction-safe code; the connection stays usable.
        write_frame(
            &mut client,
            &MirrorRequest::Install {
                sa: sa.into(),
                epoch: 1,
                format: 7,
                send_iv_next: 100,
                replay_highest_accepted: 20,
            },
            &[0xDD; 32],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (response, _): (MirrorResponse, _) = read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(
            response,
            MirrorResponse::Rejected {
                code: "mirror_conflict".into()
            }
        );

        write_frame(
            &mut client,
            &MirrorRequest::Checkpoint {
                sa: sa.into(),
                epoch: 1,
                send_iv_next: 900,
                replay_highest_accepted: 800,
            },
            &[],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (response, _): (MirrorResponse, _) = read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(response, MirrorResponse::Accepted);

        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert_eq!(takeover.resume.checkpointed_send_iv_next, 900);
        assert_eq!(takeover.keymat.expose_secret_bytes(), &[0xEE; 32]);

        write_frame(
            &mut client,
            &MirrorRequest::Withdraw {
                sa: sa.into(),
                epoch: 1,
            },
            &[],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (response, _): (MirrorResponse, _) = read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(response, MirrorResponse::Accepted);

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn secret_tails_on_non_install_frames_fail_the_connection_closed() {
        let holder = Arc::new(InMemoryStandbyHolder::new());
        let (mut client, server_task) = drive_serve_stream(holder).await;
        hello(&mut client).await;

        write_frame(
            &mut client,
            &MirrorRequest::Withdraw {
                sa: SaId::Esp { spi: 42 }.into(),
                epoch: 1,
            },
            b"smuggled-bytes",
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(SaMirrorError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn contract_version_mismatch_fails_closed_after_the_ack() {
        let holder = Arc::new(InMemoryStandbyHolder::new());
        let (mut client, server_task) = drive_serve_stream(holder).await;

        write_frame(
            &mut client,
            &MirrorRequest::Hello {
                contract_version: CONTRACT_VERSION + 1,
                node_id: "future-producer".into(),
            },
            &[],
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();
        let (ack, _): (MirrorResponse, _) = read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(
            ack,
            MirrorResponse::HelloAck {
                contract_version: CONTRACT_VERSION
            }
        );
        assert!(matches!(
            server_task.await.unwrap(),
            Err(SaMirrorError::VersionMismatch { .. })
        ));
    }
}
