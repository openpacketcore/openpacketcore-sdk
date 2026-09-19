//! Explicit RFC 5746 connection binding and RFC 6083 epoch transitions.

use super::*;
use crate::dtls12::message::{Extension, ExtensionType};
use subtle::ConstantTimeEq;

#[derive(Default)]
pub(super) struct RekeyState {
    negotiated: bool,
    client_finished: Option<[u8; 12]>,
    server_finished: Option<[u8; 12]>,
    previous_finished: Option<([u8; 12], [u8; 12])>,
}

fn binding_error() -> Error {
    Error::SecurityError(crate::SecurityError::RenegotiationBindingMismatch)
}

impl Engine {
    pub(crate) fn is_rfc6083_rekey(&self) -> bool {
        self.previous_crypto_context.is_some()
    }

    pub(crate) fn begin_rfc6083_rekey(&mut self) -> Result<(), Error> {
        if !self.config.rfc6083_rekey()
            || !self.release_app_data
            || !self.rekey.negotiated
            || self.close_notify_received
            || self.previous_crypto_context.is_some()
            || !self.queue_tx.is_empty()
            || self.rfc6083_output_barrier.is_some()
            || self.rfc6083_prepare_ccs_barrier.is_some()
            || self.rfc6083_prepare_epoch_barrier.is_some()
            || self.rfc6083_prepare_close_notify.is_some()
        {
            return Err(Error::RenegotiationAttempt);
        }
        let next = self
            .sequence_epoch_n
            .epoch
            .checked_add(1)
            .ok_or(Error::RenegotiationAttempt)?;
        let finished = (
            self.rekey.client_finished.ok_or_else(binding_error)?,
            self.rekey.server_finished.ok_or_else(binding_error)?,
        );
        self.purge_handled_queue_rx();
        if self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .any(|r| !r.is_handled() && r.record().content_type != ContentType::ApplicationData)
        {
            return Err(Error::HandshakePending);
        }
        self.previous_crypto_context = Some(self.crypto_context.restart_handshake());
        self.previous_protected_send_count = self.protected_send_count;
        self.protected_send_count = 0;
        self.sequence_epoch_0 = self.sequence_epoch_n;
        self.sequence_epoch_n = Sequence::new(next);
        self.rekey.previous_finished = Some(finished);
        self.rekey.client_finished = None;
        self.rekey.server_finished = None;
        self.peer_handshake_seq_no = 0;
        self.next_handshake_seq_no = 0;
        self.transcript.clear();
        self.flight_clear_resends();
        self.connect_timeout = Timeout::Unarmed;
        self.flight_timeout = Timeout::Disabled;
        self.release_app_data = false;
        self.peer_handshake_confirmed = false;
        Ok(())
    }

    pub(crate) fn rfc6083_epoch(&self) -> u16 {
        self.sequence_epoch_n.epoch
    }

    pub(crate) fn save_finished(&mut self, client: bool, value: [u8; 12]) {
        if self.config.rfc6083_rekey() {
            if client {
                self.rekey.client_finished = Some(value);
            } else {
                self.rekey.server_finished = Some(value);
            }
        }
    }

    /// The length-prefixed extension body for this endpoint's hello.
    pub(crate) fn renegotiation_info(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(25);
        match self.rekey.previous_finished {
            None => body.push(0),
            Some((client, server)) => {
                body.push(if self.is_client { 12 } else { 24 });
                body.extend_from_slice(&client);
                if !self.is_client {
                    body.extend_from_slice(&server);
                }
            }
        }
        body
    }

    pub(crate) fn verify_renegotiation_info(
        &mut self,
        extensions: &[Extension],
        buffer: &[u8],
        scsv: bool,
    ) -> Result<(), Error> {
        if !self.config.rfc6083_rekey() {
            return Ok(());
        }
        let mut offered = extensions
            .iter()
            .filter(|e| e.extension_type == ExtensionType::RenegotiationInfo);
        let extension = offered.next();
        if offered.next().is_some() || (scsv && self.rekey.previous_finished.is_some()) {
            return Err(binding_error());
        }
        let mut expected = Vec::with_capacity(25);
        match self.rekey.previous_finished {
            None => expected.push(0),
            Some((client, server)) => {
                expected.push(if self.is_client { 24 } else { 12 });
                expected.extend_from_slice(&client);
                if self.is_client {
                    expected.extend_from_slice(&server);
                }
            }
        }
        match extension {
            Some(extension) => {
                let actual = buffer
                    .get(extension.extension_data_range.clone())
                    .ok_or_else(binding_error)?;
                if !bool::from(actual.ct_eq(expected.as_slice())) {
                    return Err(binding_error());
                }
            }
            None if scsv && !self.is_client && self.rekey.previous_finished.is_none() => {}
            None => return Err(binding_error()),
        }
        self.rekey.negotiated = true;
        Ok(())
    }

    pub(super) fn write_context(&self, epoch: u16) -> &CryptoContext {
        if epoch == self.sequence_epoch_0.epoch {
            if let Some(previous) = &self.previous_crypto_context {
                return previous;
            }
        }
        &self.crypto_context
    }

    pub(super) fn write_context_mut(&mut self, epoch: u16) -> &mut CryptoContext {
        if epoch == self.sequence_epoch_0.epoch {
            if let Some(previous) = &mut self.previous_crypto_context {
                return previous;
            }
        }
        &mut self.crypto_context
    }

    pub(super) fn read_context(&self) -> &CryptoContext {
        self.write_context(self.peer_epoch)
    }

    pub(super) fn read_context_mut(&mut self) -> &mut CryptoContext {
        self.write_context_mut(self.peer_epoch)
    }

    pub(super) fn record_epoch(&self, relative: u16) -> u16 {
        if relative == 0 {
            self.sequence_epoch_0.epoch
        } else {
            self.sequence_epoch_n.epoch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_record_engine() -> Engine {
        let config = Arc::new(
            Config::builder()
                .rfc6083_sctp()
                .require_server_certificate_request(true)
                .dtls13_cipher_suites(&[])
                .aead_encryption_limit(3)
                .build()
                .expect("mutual profile")
                .with_rfc6083_rekey()
                .expect("opt in"),
        );
        // Synthetic record-layer keys; authenticated certificate handshakes are
        // exercised separately by the integration and kernel tests.
        let mut engine = super::super::tests::encrypted_engine(config, true);
        engine.rekey.negotiated = true;
        engine.save_finished(true, [0x11; 12]);
        engine.save_finished(false, [0x22; 12]);
        engine.release_application_data();
        engine
    }

    #[test]
    fn rekey_preserves_old_nonce_and_aead_budget_and_refuses_epoch_wrap() {
        let mut engine = ready_record_engine();
        engine
            .create_record(ContentType::ApplicationData, 1, false, |b| b.push(7))
            .expect("old encrypted data");
        let before = super::super::tests::drain_packets(&mut engine);
        assert_eq!(before.len(), 1);
        engine.begin_rfc6083_rekey().expect("start rekey");
        assert_eq!(engine.sequence_epoch_0.epoch, 1);
        assert_eq!(engine.sequence_epoch_0.sequence_number, 1);
        for content in [ContentType::Handshake, ContentType::ChangeCipherSpec] {
            engine
                .create_record(content, 0, false, |b| b.push(1))
                .expect("old-key control within original budget");
        }
        let packets = super::super::tests::drain_packets(&mut engine);
        assert_eq!(packets.len(), 2);
        assert_eq!(&packets[0][3..11], &[0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&packets[1][3..11], &[0, 1, 0, 0, 0, 0, 0, 2]);
        assert_eq!(engine.previous_protected_send_count, 3);
        assert_eq!(engine.protected_send_count, 0);
        assert!(matches!(
            engine.create_record(ContentType::Handshake, 0, false, |_| {}),
            Err(Error::CryptoError(
                crate::CryptoError::AeadEncryptionLimitReached { limit: 3 }
            ))
        ));
        assert!(engine.queue_tx.is_empty());
        let mut engine = ready_record_engine();
        engine.sequence_epoch_n.epoch = u16::MAX;
        assert!(matches!(
            engine.begin_rfc6083_rekey(),
            Err(Error::RenegotiationAttempt)
        ));
        assert_eq!(engine.sequence_epoch_n.epoch, u16::MAX);
        assert!(engine.previous_crypto_context.is_none());
    }

    #[test]
    fn independent_rfc5746_bindings_reject_wrong_previous_connection() {
        let config = Arc::new(
            Config::builder()
                .rfc6083_sctp()
                .require_server_certificate_request(true)
                .dtls13_cipher_suites(&[])
                .build()
                .expect("mutual profile")
                .with_rfc6083_rekey()
                .expect("opt in"),
        );
        let mut total = 0;
        let mut accepted = 0;
        for row in include_str!("../../../tests/dtls12/rfc5746_binding_reference.tsv")
            .lines()
            .filter(|v| !v.starts_with('#'))
        {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 5);
            let mut engine = Engine::new(Arc::clone(&config), AuthMode::Psk);
            engine.set_client(fields[0] == "client");
            if fields[1] == "rekey" {
                engine.rekey.previous_finished = Some((
                    std::array::from_fn(|i| i as u8),
                    std::array::from_fn(|i| 240 + i as u8),
                ));
            }
            let wire: Vec<u8> = if fields[3] == "-" {
                vec![]
            } else {
                (0..fields[3].len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).expect("fixture hex"))
                    .collect()
            };
            let mut extensions = Vec::new();
            let mut offset = 0;
            while offset < wire.len() {
                let (remaining, extension) = Extension::parse(&wire[offset..], offset)
                    .expect("independent extension framing");
                offset = wire.len() - remaining.len();
                extensions.push(extension);
            }
            let actual = engine.verify_renegotiation_info(&extensions, &wire, fields[2] == "1");
            assert_eq!(actual.is_ok(), fields[4] == "1", "fixture {row}");
            if actual.is_ok() {
                accepted += 1;
            }
            total += 1;
        }
        assert_eq!((total, accepted), (100, 5));
    }
}
