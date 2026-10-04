//! Bounded association-local correlation, never receive-order matching.

use std::collections::BTreeMap;

use super::super::{parse_dtls_record_bounds, DiameterTlsError, SctpUserMessage};

pub(in crate::dtls) struct RecordStreams {
    count: u16,
    capacity: usize,
    pending: BTreeMap<(u16, u64), u16>,
    pub(in crate::dtls) outbound: u16,
}

impl Default for RecordStreams {
    fn default() -> Self {
        Self::new(1, 0)
    }
}

impl RecordStreams {
    pub(in crate::dtls) fn new(count: u16, capacity: usize) -> Self {
        Self {
            count,
            capacity,
            pending: BTreeMap::new(),
            outbound: 0,
        }
    }

    pub(in crate::dtls) fn count(&self) -> u16 {
        self.count
    }

    pub(in crate::dtls) fn remember(
        &mut self,
        message: &SctpUserMessage,
    ) -> Result<(), DiameterTlsError> {
        if self.count == 1 {
            return Ok(());
        }
        let payload = message.payload();
        let bounds = parse_dtls_record_bounds(payload).ok_or(DiameterTlsError::Transport)?;
        if bounds.content_type != Some(23) {
            return Ok(());
        }
        if bounds.unified || bounds.epoch == 0 || payload.len() < 13 {
            return Err(DiameterTlsError::Transport);
        }
        let sequence = u64::from_be_bytes([
            0,
            0,
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
        ]);
        let key = (bounds.epoch, sequence);
        if let Some(stream) = self.pending.get(&key) {
            // A pending duplicate must never replace authenticated carrier
            // metadata. The engine owns duplicate record handling.
            return if *stream == message.stream_id() {
                Ok(())
            } else {
                Err(DiameterTlsError::Transport)
            };
        }
        if self.pending.len() >= self.capacity {
            return Err(DiameterTlsError::Transport);
        }
        self.pending.insert(key, message.stream_id());
        Ok(())
    }

    pub(in crate::dtls) fn take(
        &mut self,
        record: Option<dimpl::Rfc6083ApplicationRecord>,
        queued_plaintexts: usize,
    ) -> Result<u16, DiameterTlsError> {
        if self.count == 1 {
            return Ok(0);
        }
        if queued_plaintexts >= self.capacity {
            return Err(DiameterTlsError::Transport);
        }
        let record = record.ok_or(DiameterTlsError::Transport)?;
        self.pending
            .remove(&(record.epoch(), record.sequence_number()))
            .ok_or(DiameterTlsError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls::{handle_received_record, SctpDeliveryOrder};
    use crate::dtls_tests::{dtls_material, generic::generic_pair};
    use crate::rfc6083::{PayloadProtocol, Policy};
    use bytes::Bytes;
    use std::time::Duration;
    use tokio::time::Instant;

    async fn buffered_pair(
        material: &crate::dtls_tests::TestMaterial,
        capacity: usize,
    ) -> (super::super::Connection, super::super::Connection) {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, capacity)
            .expect("bounded stream policy");
        let (client, server, _) = generic_pair(material, policy, policy).await;
        (client, server)
    }

    #[test]
    fn independent_carrier_framing_reference_matches_bounded_profile() {
        let corpus = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rfc6083/streams.tsv"
        ));
        let mut cases = 0;
        for row in corpus.lines().filter(|row| !row.starts_with('#')) {
            let columns: Vec<_> = row.split('\t').collect();
            assert_eq!(columns.len(), 10);
            let count: u16 = columns[0].parse().expect("count");
            let ppid = columns[1].parse().expect("PPID");
            let stream = columns[2].parse().expect("stream");
            let kind = columns[5].parse().expect("content type");
            let epoch: u16 = columns[6].parse().expect("epoch");
            let version = u16::from_str_radix(columns[8], 16).expect("record version");
            let mut payload = vec![kind];
            payload.extend_from_slice(&version.to_be_bytes());
            payload.extend_from_slice(&epoch.to_be_bytes());
            payload.extend_from_slice(&[0, 0x10, 0x20, 0x30, 0x40, 0x50]);
            payload.extend_from_slice(&16_u16.to_be_bytes());
            payload.extend(0..16);
            match columns[7] {
                "complete" => {}
                "short" => {
                    payload.pop();
                }
                "trailing" => payload.push(0),
                "oversized" => payload.resize(crate::MAX_DTLS_SCTP_RECORD_BYTES + 1, 0),
                _ => panic!("invalid independent shape"),
            }
            let message = SctpUserMessage::new(
                payload.into(),
                ppid,
                stream,
                if columns[3] == "ordered" {
                    SctpDeliveryOrder::Ordered
                } else {
                    SctpDeliveryOrder::Unordered
                },
                columns[4] == "payload",
                columns[4] == "control",
                columns[4] == "notification",
            );
            let result = crate::dtls::validate_received_record_on_streams(&message, 66, count);
            let actual = match result {
                Ok(_) => "framing-admitted".to_owned(),
                Err(error) => crate::rfc6083::Error::from(error).to_string(),
            };
            assert_eq!(actual, columns[9], "independent framing disposition");
            cases += 1;
        }
        assert_eq!(cases, 18560);
    }

    #[tokio::test]
    async fn reversed_buffered_records_keep_exact_streams_and_empty_payloads() {
        for reverse_direction in [false, true] {
            let material = dtls_material();
            let (mut client, mut server) = buffered_pair(&material, 8).await;
            let (sender, receiver) = if reverse_direction {
                (&mut server, &mut client)
            } else {
                (&mut client, &mut server)
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            let payloads: [&[u8]; 4] = [b"first", b"", b"third", b"fourth"];
            let streams = [7, 2, 0, 15];
            let mut messages = Vec::new();
            for (stream, payload) in streams.into_iter().zip(payloads) {
                sender
                    .send_on_stream(stream, payload, deadline)
                    .await
                    .expect("send");
                messages.push(
                    receiver
                        .io
                        .receive_message()
                        .await
                        .expect("carrier")
                        .expect("record"),
                );
            }
            // Seed the real engine's buffering path in reversed arrival order.
            // Output order comes from the engine, not the carrier queue.
            for message in messages.iter().rev() {
                handle_received_record(
                    &mut receiver.engine,
                    &mut receiver.pump,
                    message,
                    66,
                    DiameterTlsError::Transport,
                )
                .expect("buffer real encrypted record");
            }
            assert_eq!(receiver.pump.streams.pending.len(), 4);
            for (stream, payload) in streams.into_iter().zip(payloads) {
                let message = receiver
                    .receive(deadline)
                    .await
                    .expect("exact record correlation");
                assert_eq!(message.stream_id(), stream);
                assert_eq!(message.as_bytes(), payload);
            }
            assert!(receiver.pump.streams.pending.is_empty());
            assert!(receiver.pump.inbound.is_empty());
        }
    }

    #[tokio::test]
    async fn pending_duplicate_cannot_overwrite_stream_and_capacity_is_exact() {
        let material = dtls_material();
        let (mut sender, mut receiver) = buffered_pair(&material, 2).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut messages = Vec::new();
        for stream in [1, 2, 3] {
            sender
                .send_on_stream(stream, b"synthetic", deadline)
                .await
                .expect("send");
            messages.push(
                receiver
                    .io
                    .receive_message()
                    .await
                    .expect("carrier")
                    .expect("record"),
            );
        }
        for message in &messages[..2] {
            receiver
                .pump
                .streams
                .remember(message)
                .expect("within capacity");
        }
        receiver
            .pump
            .streams
            .remember(&messages[0])
            .expect("same pending metadata");
        let changed = SctpUserMessage::new(
            Bytes::copy_from_slice(messages[0].payload()),
            66,
            3,
            SctpDeliveryOrder::Ordered,
            false,
            false,
            false,
        );
        assert_eq!(
            receiver.pump.streams.remember(&changed),
            Err(DiameterTlsError::Transport)
        );
        assert_eq!(
            receiver.pump.streams.remember(&messages[2]),
            Err(DiameterTlsError::Transport)
        );
        assert_eq!(receiver.pump.streams.pending.len(), 2);
        for message in &messages[..2] {
            handle_received_record(
                &mut receiver.engine,
                &mut receiver.pump,
                message,
                66,
                DiameterTlsError::Transport,
            )
            .expect("original mapping retained");
        }
        for stream in [1, 2] {
            assert_eq!(
                receiver
                    .receive(deadline)
                    .await
                    .expect("receive")
                    .stream_id(),
                stream
            );
        }
        assert!(receiver.pump.streams.pending.is_empty());
        handle_received_record(
            &mut receiver.engine,
            &mut receiver.pump,
            &messages[2],
            66,
            DiameterTlsError::Transport,
        )
        .expect("capacity reused after exact record consumption");
        assert_eq!(
            receiver
                .receive(deadline)
                .await
                .expect("receive")
                .stream_id(),
            3
        );
    }

    #[tokio::test]
    async fn missing_mapping_or_plaintext_capacity_never_releases_a_record() {
        for lose_mapping in [true, false] {
            let material = dtls_material();
            let (mut sender, mut receiver) = buffered_pair(&material, 1).await;
            let deadline = Instant::now() + Duration::from_secs(5);
            sender
                .send_on_stream(1, b"synthetic", deadline)
                .await
                .expect("send");
            let message = receiver
                .io
                .receive_message()
                .await
                .expect("carrier")
                .expect("record");
            handle_received_record(
                &mut receiver.engine,
                &mut receiver.pump,
                &message,
                66,
                DiameterTlsError::Transport,
            )
            .expect("buffer real record");
            if lose_mapping {
                receiver.pump.streams.pending.clear();
            } else {
                crate::dtls::poll_engine(
                    &mut receiver.engine,
                    None,
                    &mut receiver.pump,
                    &mut receiver.buffer,
                )
                .expect("first authentic plaintext queued");
                assert_eq!(receiver.pump.inbound.len(), 1);
                sender
                    .send_on_stream(2, b"second", deadline)
                    .await
                    .expect("send");
                let message = receiver
                    .io
                    .receive_message()
                    .await
                    .expect("carrier")
                    .expect("record");
                handle_received_record(
                    &mut receiver.engine,
                    &mut receiver.pump,
                    &message,
                    66,
                    DiameterTlsError::Transport,
                )
                .expect("next authentic record buffered");
            }
            assert_eq!(
                receiver.receive(deadline).await.err(),
                Some(crate::rfc6083::Error::Transport)
            );
            assert_eq!(
                receiver.readback().err(),
                Some(crate::rfc6083::Error::ConnectionClosed)
            );
        }
    }

    #[tokio::test]
    async fn changed_header_ciphertext_or_tag_cannot_release_mapped_plaintext() {
        let material = dtls_material();
        let mut cases = 0;
        for (reverse, stream) in [(false, 0), (false, 3), (true, 0), (true, 3)] {
            for offset in [0, 1, 2, 3, 4, 5, 10, 13, 14, 20, 30, 40] {
                for bit in 0..8 {
                    let (mut client, mut server) = buffered_pair(&material, 2).await;
                    let (sender, receiver) = if reverse {
                        (&mut server, &mut client)
                    } else {
                        (&mut client, &mut server)
                    };
                    let deadline = Instant::now() + Duration::from_secs(5);
                    sender
                        .send_on_stream(stream, b"synthetic-record-body", deadline)
                        .await
                        .expect("authentic send");
                    let message = receiver
                        .io
                        .receive_message()
                        .await
                        .expect("carrier")
                        .expect("record");
                    let mut payload = message.payload().to_vec();
                    assert!(offset < payload.len());
                    payload[offset] ^= 1 << bit;
                    let changed = SctpUserMessage::new(
                        payload.into(),
                        66,
                        stream,
                        SctpDeliveryOrder::Ordered,
                        false,
                        false,
                        false,
                    );
                    let _ = handle_received_record(
                        &mut receiver.engine,
                        &mut receiver.pump,
                        &changed,
                        66,
                        DiameterTlsError::Transport,
                    );
                    let _ = crate::dtls::poll_engine(
                        &mut receiver.engine,
                        None,
                        &mut receiver.pump,
                        &mut receiver.buffer,
                    );
                    assert!(
                        receiver.pump.inbound.is_empty(),
                        "mutation cannot release a plaintext/stream pair: offset {offset}, bit {bit}"
                    );
                    assert!(receiver.pump.streams.pending.len() <= 1);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 384);
    }
}
