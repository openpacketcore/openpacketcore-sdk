//! DTLS 1.2 cryptographic context for a session.

use std::sync::Arc;

use arrayvec::ArrayVec;
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::buffer::{Buf, TmpBuf, ToBuf};
use crate::crypto;
use crate::crypto::SrtpProfile;
use crate::crypto::{Aad, Iv, Nonce};
use crate::dtls12::message::DigitallySigned;
use crate::dtls12::message::{CurveType, Dtls12CipherSuite, HashAlgorithm};
use crate::dtls12::message::{NamedGroup, SignatureAlgorithm};

#[derive(Debug)]
struct UnavailableSigningKey;

impl crypto::SigningKey for UnavailableSigningKey {
    fn sign(
        &mut self,
        _data: &[u8],
        _hash_alg: HashAlgorithm,
        _out: &mut Buf,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidPrivateKey)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        &[]
    }
}

pub(crate) fn unavailable_signing_key() -> Box<dyn crypto::SigningKey> {
    Box::new(UnavailableSigningKey)
}

struct PrfBuffers<'a> {
    out: &'a mut Buf,
    scratch: &'a mut Buf,
}

impl<'a> PrfBuffers<'a> {
    fn new(out: &'a mut Buf, scratch: &'a mut Buf) -> Self {
        Self { out, scratch }
    }

    fn split(&mut self) -> (&mut Buf, &mut Buf) {
        (self.out, self.scratch)
    }
}

impl Drop for PrfBuffers<'_> {
    fn drop(&mut self) {
        self.out.zeroize();
        self.scratch.zeroize();
    }
}

/// DTLS 1.2 crypto context holding negotiated keys and ciphers for a session.
pub struct CryptoContext {
    /// Configuration (contains crypto provider)
    config: Arc<crate::Config>,

    /// Key exchange mechanism
    key_exchange: Option<Box<dyn crypto::ActiveKeyExchange>>,

    /// Our public key from the key exchange (stored for reuse)
    key_exchange_public_key: Option<Vec<u8>>,

    /// Group info from the key exchange (stored for reuse)
    key_exchange_group: Option<NamedGroup>,

    /// Client write key
    client_write_key: Option<Buf>,

    /// Server write key
    server_write_key: Option<Buf>,

    /// Client write IV (4 bytes for AES-GCM, 12 bytes for ChaCha20-Poly1305)
    client_write_iv: Option<Iv>,

    /// Server write IV (4 bytes for AES-GCM, 12 bytes for ChaCha20-Poly1305)
    server_write_iv: Option<Iv>,

    /// Client MAC key (not used for AEAD ciphers)
    client_mac_key: Option<Buf>,

    /// Server MAC key (not used for AEAD ciphers)
    server_mac_key: Option<Buf>,

    /// Master secret
    master_secret: Option<ArrayVec<u8, 128>>,

    /// Pre-master secret (temporary)
    pre_master_secret: Option<Buf>,

    /// Client cipher
    client_cipher: Option<Box<dyn crypto::Cipher>>,

    /// Server cipher
    server_cipher: Option<Box<dyn crypto::Cipher>>,

    /// Authentication mode: certificate or PSK.
    auth: AuthMode,

    /// Resolved PSK value (set during handshake after identity exchange)
    psk: Option<Vec<u8>>,

    /// Client random (needed for SRTP key export per RFC 5705)
    client_random: Option<ArrayVec<u8, 32>>,

    /// Server random (needed for SRTP key export per RFC 5705)
    server_random: Option<ArrayVec<u8, 32>>,
}

/// Authentication mode for a DTLS 1.2 session.
pub enum AuthMode {
    /// Certificate-based authentication (ECDHE_ECDSA suites).
    Certificate {
        /// DER-encoded leaf and intermediate certificates in wire order.
        certificates: Vec<Vec<u8>>,
        /// Parsed signing key for the certificate.
        private_key: Box<dyn crypto::SigningKey>,
    },
    /// Pre-shared key authentication (PSK suites).
    /// The actual PSK value is resolved during the handshake via [`CryptoContext::set_psk`].
    Psk,
}

impl CryptoContext {
    /// Create a new crypto context with the given authentication mode.
    pub fn new(auth: AuthMode, config: Arc<crate::Config>) -> Self {
        CryptoContext {
            config,
            key_exchange: None,
            key_exchange_public_key: None,
            key_exchange_group: None,
            client_write_key: None,
            server_write_key: None,
            client_write_iv: None,
            server_write_iv: None,
            client_mac_key: None,
            server_mac_key: None,
            master_secret: None,
            pre_master_secret: None,
            client_cipher: None,
            server_cipher: None,
            auth,
            psk: None,
            client_random: None,
            server_random: None,
        }
    }

    pub fn provider(&self) -> &crypto::CryptoProvider {
        self.config.crypto_provider()
    }

    /// Generate key exchange public key
    pub fn maybe_init_key_exchange(&mut self) -> Result<&[u8], CryptoError> {
        // If we already have the public key stored, return it
        if let Some(ref pk) = self.key_exchange_public_key {
            return Ok(pk);
        }

        // Otherwise, get it from the key exchange and store it
        match &self.key_exchange {
            Some(ke) => {
                let pub_key = ke.pub_key().to_vec();
                let group = ke.group();
                self.key_exchange_public_key = Some(pub_key);
                self.key_exchange_group = Some(group);
                self.key_exchange_public_key
                    .as_deref()
                    .ok_or(CryptoError::KeyExchangeNotInitialized)
            }
            None => Err(CryptoError::KeyExchangeNotInitialized),
        }
    }

    /// Process peer's public key and compute shared secret
    pub fn compute_shared_secret(
        &mut self,
        peer_public_key: &[u8],
        buf: &mut Buf,
    ) -> Result<(), CryptoError> {
        let ke = self
            .key_exchange
            .take()
            .ok_or(CryptoError::KeyExchangeNotInitialized)?;
        if let Err(error) = ke.complete(peer_public_key, buf) {
            buf.zeroize();
            return Err(error);
        }
        self.pre_master_secret = Some(core::mem::take(buf));
        // Note: we keep key_exchange_public_key since it may be needed later
        Ok(())
    }

    /// Set the resolved PSK value for this session.
    pub fn set_psk(&mut self, psk: Vec<u8>) {
        if let Some(mut previous) = self.psk.replace(psk) {
            previous.zeroize();
        }
    }

    /// Compute PSK pre-master secret per RFC 4279 §2.
    ///
    /// Format: `uint16(N) || zeros(N) || uint16(N) || PSK(N)`
    /// where N is the PSK length.
    pub fn compute_psk_pre_master_secret(&mut self) -> Result<(), CryptoError> {
        let mut psk = self.psk.take().ok_or(CryptoError::PskNotSet)?;
        let n = psk.len();
        if n > u16::MAX as usize {
            psk.zeroize();
            return Err(CryptoError::KeyingMaterialTooLong);
        }
        // Total: 2 + N + 2 + N = 2N + 4
        let mut pms = Buf::new();
        pms.extend_from_slice(&(n as u16).to_be_bytes());
        pms.resize(pms.len() + n, 0);
        pms.extend_from_slice(&(n as u16).to_be_bytes());
        pms.extend_from_slice(&psk);
        self.pre_master_secret = Some(pms);
        psk.zeroize();
        Ok(())
    }

    /// Initialize ECDHE key exchange (server role) and return our ephemeral public key
    pub fn init_ecdh_server(
        &mut self,
        named_group: NamedGroup,
        kx_buf: &mut Buf,
    ) -> Result<&[u8], CryptoError> {
        // Find the matching key exchange group from the provider
        let kx_group = self
            .provider()
            .supported_kx_groups()
            .find(|g| g.name() == named_group)
            .ok_or(CryptoError::UnsupportedEcdheNamedGroup(named_group))?;

        kx_buf.clear();
        self.key_exchange = Some(kx_group.start_exchange(core::mem::take(kx_buf))?);
        self.maybe_init_key_exchange()
    }

    /// Process a ServerKeyExchange message and set up key exchange accordingly
    pub fn process_ecdh_params(
        &mut self,
        group: NamedGroup,
        server_public: &[u8],
        kx_buf: &mut Buf,
    ) -> Result<(), CryptoError> {
        // Find the matching key exchange group from the provider
        let kx_group = self
            .provider()
            .supported_kx_groups()
            .find(|g| g.name() == group)
            .ok_or(CryptoError::UnsupportedEcdheNamedGroup(group))?;

        // Create a new ECDH key exchange
        kx_buf.clear();
        self.key_exchange = Some(kx_group.start_exchange(core::mem::take(kx_buf))?);

        // Generate our keypair
        let _our_public = self.maybe_init_key_exchange()?;

        // Compute shared secret with the server's public key
        self.compute_shared_secret(server_public, kx_buf)?;

        Ok(())
    }

    /// Derive master secret using Extended Master Secret (RFC 7627)
    pub fn derive_extended_master_secret(
        &mut self,
        session_hash: &[u8],
        hash: HashAlgorithm,
        out: &mut Buf,
        scratch: &mut Buf,
    ) -> Result<(), CryptoError> {
        trace!("Deriving extended master secret");
        let mut buffers = PrfBuffers::new(out, scratch);
        let (out, scratch) = buffers.split();
        let pms = self
            .pre_master_secret
            .take()
            .ok_or(CryptoError::PreMasterSecretNotAvailable)?;
        crypto::prf_hkdf::prf_tls12(
            self.provider().hmac_provider,
            &pms,
            "extended master secret",
            session_hash,
            out,
            48,
            scratch,
            hash,
        )?;
        let mut master_secret = ArrayVec::new();
        master_secret
            .try_extend_from_slice(out)
            .map_err(|_| CryptoError::MasterSecretTooLong)?;
        if let Some(previous) = self.master_secret.as_mut() {
            previous.as_mut_slice().zeroize();
        }
        self.master_secret = Some(master_secret);
        Ok(())
    }

    /// Derive keys for encryption/decryption
    pub fn derive_keys(
        &mut self,
        cipher_suite: Dtls12CipherSuite,
        client_random: &[u8],
        server_random: &[u8],
        key_block: &mut Buf,
        scratch: &mut Buf,
    ) -> Result<(), CryptoError> {
        let mut buffers = PrfBuffers::new(key_block, scratch);
        let (key_block, scratch) = buffers.split();
        let Some(master_secret) = &self.master_secret else {
            return Err(CryptoError::MasterSecretNotAvailable);
        };

        // Store the randoms for later SRTP key export (RFC 5705)
        let mut client_random_arr = ArrayVec::new();
        client_random_arr
            .try_extend_from_slice(client_random)
            .map_err(|_| CryptoError::KeyingMaterialTooLong)?;
        self.client_random = Some(client_random_arr);

        let mut server_random_arr = ArrayVec::new();
        server_random_arr
            .try_extend_from_slice(server_random)
            .map_err(|_| CryptoError::KeyingMaterialTooLong)?;
        self.server_random = Some(server_random_arr);

        // Find the cipher suite from the provider
        let supported_cipher_suite = self
            .provider()
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == cipher_suite)
            .ok_or(CryptoError::UnsupportedCipherSuite(cipher_suite))?;

        // Get key sizes from the provider
        let (mac_key_len, enc_key_len, fixed_iv_len) = supported_cipher_suite.key_lengths();

        // Calculate total key material length
        let key_material_len = 2 * (mac_key_len + enc_key_len + fixed_iv_len);

        // Compute seed for key expansion: server_random + client_random
        let mut seed = Zeroizing::new([0u8; 64]);
        seed[..32].copy_from_slice(server_random);
        seed[32..].copy_from_slice(client_random);

        // Generate key material using PRF
        crypto::prf_hkdf::prf_tls12(
            self.provider().hmac_provider,
            master_secret,
            "key expansion",
            seed.as_slice(),
            key_block,
            key_material_len,
            scratch,
            cipher_suite.hash_algorithm(),
        )?;

        // Split key material
        let mut offset = 0;

        // Extract MAC keys (if used)
        if mac_key_len > 0 {
            self.client_mac_key = Some(key_block[offset..offset + mac_key_len].to_buf());
            offset += mac_key_len;
            self.server_mac_key = Some(key_block[offset..offset + mac_key_len].to_buf());
            offset += mac_key_len;
        }

        // Extract encryption keys
        self.client_write_key = Some(key_block[offset..offset + enc_key_len].to_buf());
        offset += enc_key_len;
        self.server_write_key = Some(key_block[offset..offset + enc_key_len].to_buf());
        offset += enc_key_len;

        // Extract IVs
        self.client_write_iv = Some(Iv::new(&key_block[offset..offset + fixed_iv_len])?);
        offset += fixed_iv_len;
        self.server_write_iv = Some(Iv::new(&key_block[offset..offset + fixed_iv_len])?);

        // Initialize ciphers using the provider
        let client_write_key = self
            .client_write_key
            .as_deref()
            .ok_or(CryptoError::ClientCipherNotInitialized)?;
        self.client_cipher = Some(supported_cipher_suite.create_cipher(client_write_key)?);

        let server_write_key = self
            .server_write_key
            .as_deref()
            .ok_or(CryptoError::ServerCipherNotInitialized)?;
        self.server_cipher = Some(supported_cipher_suite.create_cipher(server_write_key)?);

        Ok(())
    }

    /// Encrypt data (client to server)
    pub fn encrypt_client_to_server(
        &mut self,
        plaintext: &mut Buf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        match &mut self.client_cipher {
            Some(cipher) => cipher.encrypt(plaintext, aad, nonce),
            None => Err(CryptoError::ClientCipherNotInitialized),
        }
    }

    /// Decrypt data (server to client)
    pub fn decrypt_server_to_client(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        match &mut self.server_cipher {
            Some(cipher) => cipher.decrypt(ciphertext, aad, nonce),
            None => Err(CryptoError::ServerCipherNotInitialized),
        }
    }

    /// Encrypt data (server to client)
    pub fn encrypt_server_to_client(
        &mut self,
        plaintext: &mut Buf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        match &mut self.server_cipher {
            Some(cipher) => cipher.encrypt(plaintext, aad, nonce),
            None => Err(CryptoError::ServerCipherNotInitialized),
        }
    }

    /// Decrypt data (client to server)
    pub fn decrypt_client_to_server(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        match &mut self.client_cipher {
            Some(cipher) => cipher.decrypt(ciphertext, aad, nonce),
            None => Err(CryptoError::ClientCipherNotInitialized),
        }
    }

    /// Serialize client certificate for authentication.
    ///
    /// The state machine invokes this only for certificate-authenticated
    /// suites. Chains that exceed the TLS 24-bit vector limits fail closed.
    pub fn serialize_client_certificate(&self, output: &mut Buf) -> Result<(), CryptoError> {
        let AuthMode::Certificate { certificates, .. } = &self.auth else {
            return Err(CryptoError::NoPrivateKeyConfigured);
        };
        if certificates.is_empty() || certificates.len() > super::message::MAX_CERTIFICATE_COUNT {
            return Err(CryptoError::CertificateChainTooLarge);
        }
        let mut total_len = 0_usize;
        let mut aggregate_der_len = 0_usize;
        for certificate in certificates {
            if certificate.is_empty() || certificate.len() > super::message::MAX_CERTIFICATE_BYTES {
                return Err(CryptoError::CertificateChainTooLarge);
            }
            aggregate_der_len = aggregate_der_len
                .checked_add(certificate.len())
                .ok_or(CryptoError::CertificateChainTooLarge)?;
            if aggregate_der_len > super::message::MAX_CERTIFICATE_CHAIN_BYTES {
                return Err(CryptoError::CertificateChainTooLarge);
            }
            total_len = total_len
                .checked_add(3 + certificate.len())
                .ok_or(CryptoError::CertificateChainTooLarge)?;
        }
        if total_len > super::message::MAX_CERTIFICATE_LIST_BYTES {
            return Err(CryptoError::CertificateChainTooLarge);
        }
        output.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);
        for certificate in certificates {
            output.extend_from_slice(&(certificate.len() as u32).to_be_bytes()[1..]);
            output.extend_from_slice(certificate);
        }
        Ok(())
    }

    /// Sign the provided data using the client's private key.
    /// Returns an error if no private key is configured (PSK-only mode).
    pub fn sign_data(
        &mut self,
        data: &[u8],
        hash_alg: HashAlgorithm,
        out: &mut Buf,
    ) -> Result<(), CryptoError> {
        let AuthMode::Certificate { private_key, .. } = &mut self.auth else {
            return Err(CryptoError::NoPrivateKeyConfigured);
        };
        private_key.sign(data, hash_alg, out)
    }

    /// Generate verify data for a Finished message using PRF
    pub fn generate_verify_data(
        &self,
        handshake_hash: &[u8],
        is_client: bool,
        hash: HashAlgorithm,
        out: &mut Buf,
        scratch: &mut Buf,
    ) -> Result<ArrayVec<u8, 128>, CryptoError> {
        let mut buffers = PrfBuffers::new(out, scratch);
        let (out, scratch) = buffers.split();
        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err(CryptoError::MasterSecretNotAvailable),
        };

        let label = if is_client {
            "client finished"
        } else {
            "server finished"
        };

        // Generate 12 bytes of verify data using PRF
        crypto::prf_hkdf::prf_tls12(
            self.provider().hmac_provider,
            master_secret,
            label,
            handshake_hash,
            out,
            12,
            scratch,
            hash,
        )?;
        let mut verify_data = ArrayVec::new();
        verify_data
            .try_extend_from_slice(out)
            .map_err(|_| CryptoError::VerifyDataTooLong)?;
        Ok(verify_data)
    }

    /// Extract SRTP keying material from the master secret
    /// This is per RFC 5764 (DTLS-SRTP) section 4.2 and RFC 5705 (TLS Exporter)
    pub fn extract_srtp_keying_material(
        &self,
        profile: SrtpProfile,
        hash: HashAlgorithm,
        out: &mut Buf,
        scratch: &mut Buf,
    ) -> Result<ArrayVec<u8, 88>, CryptoError> {
        const DTLS_SRTP_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";
        let mut buffers = PrfBuffers::new(out, scratch);
        let (out, scratch) = buffers.split();

        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err(CryptoError::MasterSecretNotAvailable),
        };

        let client_random = match &self.client_random {
            Some(cr) => cr,
            None => return Err(CryptoError::ClientRandomNotAvailable),
        };

        let server_random = match &self.server_random {
            Some(sr) => sr,
            None => return Err(CryptoError::ServerRandomNotAvailable),
        };

        // Per RFC 5705, the exporter uses: PRF(master_secret, label, client_random + server_random)
        // The seed for DTLS-SRTP exporter is client_random + server_random (no additional context)
        let mut seed = Zeroizing::new(Vec::with_capacity(64));
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        crypto::prf_hkdf::prf_tls12(
            self.provider().hmac_provider,
            master_secret,
            DTLS_SRTP_KEY_LABEL,
            &seed,
            out,
            profile.keying_material_len(),
            scratch,
            hash,
        )?;
        let mut keying_material = ArrayVec::new();
        keying_material
            .try_extend_from_slice(out)
            .map_err(|_| CryptoError::KeyingMaterialTooLong)?;

        Ok(keying_material)
    }

    /// Derive the RFC 6083 endpoint-pair shared secret.
    pub fn extract_rfc6083_keying_material(
        &self,
        hash: HashAlgorithm,
        out: &mut Buf,
        scratch: &mut Buf,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        const LABEL: &str = "EXPORTER_DTLS_OVER_SCTP";
        const MATERIAL_BYTES: usize = 64;
        let mut buffers = PrfBuffers::new(out, scratch);
        let (out, scratch) = buffers.split();

        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or(CryptoError::MasterSecretNotAvailable)?;
        let client_random = self
            .client_random
            .as_ref()
            .ok_or(CryptoError::ClientRandomNotAvailable)?;
        let server_random = self
            .server_random
            .as_ref()
            .ok_or(CryptoError::ServerRandomNotAvailable)?;

        let mut seed = Zeroizing::new(Vec::with_capacity(64));
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        crypto::prf_hkdf::prf_tls12(
            self.provider().hmac_provider,
            master_secret,
            LABEL,
            &seed,
            out,
            MATERIAL_BYTES,
            scratch,
            hash,
        )?;
        let material = Zeroizing::new(out.to_vec());
        Ok(material)
    }

    /// Signature algorithm for the configured private key.
    /// Returns None in PSK-only mode.
    pub fn signature_algorithm(&self) -> Option<SignatureAlgorithm> {
        match &self.auth {
            AuthMode::Certificate { private_key, .. } => Some(private_key.algorithm()),
            AuthMode::Psk => None,
        }
    }

    /// Default hash algorithm for the configured private key.
    /// Returns None in PSK-only mode.
    pub fn private_key_default_hash_algorithm(&self) -> Option<HashAlgorithm> {
        match &self.auth {
            AuthMode::Certificate { private_key, .. } => Some(private_key.hash_algorithm()),
            AuthMode::Psk => None,
        }
    }

    /// Hash algorithms the configured private key can sign with.
    /// Returns an empty slice in PSK-only mode.
    pub fn private_key_supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        match &self.auth {
            AuthMode::Certificate { private_key, .. } => private_key.supported_hash_algorithms(),
            AuthMode::Psk => &[],
        }
    }

    /// Create a hash context for the given algorithm
    pub fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn crypto::HashContext> {
        self.provider().hash_provider.create_hash(algorithm)
    }

    /// Get the key exchange group info (curve type and named group).
    pub fn get_key_exchange_group_info(&self) -> Option<(CurveType, NamedGroup)> {
        // Use stored group if available (after key exchange is consumed)
        if let Some(group) = self.key_exchange_group {
            return Some((CurveType::NamedCurve, group));
        }

        // Otherwise get it from the active key exchange
        let Some(ke) = &self.key_exchange else {
            return None;
        };
        Some((CurveType::NamedCurve, ke.group()))
    }

    /// Check if the client's private key is compatible with a given cipher suite.
    pub fn is_cipher_suite_compatible(&self, cipher_suite: Dtls12CipherSuite) -> bool {
        match (&self.auth, cipher_suite.signature_algorithm()) {
            // Certificate-based suite needs a matching private key
            (AuthMode::Certificate { private_key, .. }, Some(sig_alg)) => {
                sig_alg == private_key.algorithm()
            }
            // PSK suite is only compatible in PSK mode
            (AuthMode::Psk, None) => true,
            // Mismatch: cert context + PSK suite, or PSK context + cert suite
            _ => false,
        }
    }

    /// Get the client write IV if derived.
    pub fn get_client_write_iv(&self) -> Option<Iv> {
        self.client_write_iv
    }

    /// Get the server write IV if derived.
    pub fn get_server_write_iv(&self) -> Option<Iv> {
        self.server_write_iv
    }

    /// Verify a DigitallySigned structure against a certificate's public key.
    pub fn verify_signature(
        &self,
        data: &Buf,
        signature: &DigitallySigned,
        signature_buf: &[u8],
        cert_der: &[u8],
    ) -> Result<(), CryptoError> {
        self.provider().signature_verification.verify_signature(
            cert_der,
            data,
            signature.signature(signature_buf),
            signature.algorithm.hash,
            signature.algorithm.signature,
        )
    }
}

impl CryptoContext {
    fn zeroize_secrets(&mut self) {
        // Drop provider-owned cipher/key-exchange handles before wiping the
        // raw key bytes from which they were constructed.
        self.client_cipher = None;
        self.server_cipher = None;
        self.key_exchange = None;
        for secret in [
            &mut self.client_write_key,
            &mut self.server_write_key,
            &mut self.client_mac_key,
            &mut self.server_mac_key,
            &mut self.pre_master_secret,
        ] {
            if let Some(secret) = secret.as_mut() {
                secret.zeroize();
            }
            *secret = None;
        }
        if let Some(master_secret) = self.master_secret.as_mut() {
            master_secret.as_mut_slice().zeroize();
        }
        self.master_secret = None;
        if let Some(psk) = self.psk.as_mut() {
            psk.zeroize();
        }
        self.psk = None;
        if let Some(iv) = self.client_write_iv.as_mut() {
            iv.zeroize();
        }
        self.client_write_iv = None;
        if let Some(iv) = self.server_write_iv.as_mut() {
            iv.zeroize();
        }
        self.server_write_iv = None;
    }
}

impl Drop for CryptoContext {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[cfg(feature = "rcgen")]
    fn cert_auth_mode(config: &Config) -> AuthMode {
        let cert = crate::certificate::generate_self_signed_certificate().expect("generate cert");
        let private_key = config
            .crypto_provider()
            .key_provider
            .load_private_key(&cert.private_key)
            .expect("parse key");
        AuthMode::Certificate {
            certificates: vec![cert.certificate.clone()],
            private_key,
        }
    }

    #[test]
    #[cfg(feature = "rcgen")]
    fn certificate_mode_rejects_psk_suites() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let auth = cert_auth_mode(&config);
        let ctx = CryptoContext::new(auth, config);

        for suite in Dtls12CipherSuite::supported() {
            if suite.is_psk() {
                assert!(
                    !ctx.is_cipher_suite_compatible(*suite),
                    "Certificate-mode context must reject PSK suite {:?}",
                    suite
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "rcgen")]
    fn certificate_mode_accepts_ecdhe_suites() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let auth = cert_auth_mode(&config);
        let ctx = CryptoContext::new(auth, config);

        // At least one ECDHE_ECDSA suite should be compatible
        assert!(
            Dtls12CipherSuite::supported()
                .iter()
                .filter(|s| !s.is_psk())
                .any(|s| ctx.is_cipher_suite_compatible(*s)),
            "Certificate-mode context must accept at least one ECDHE suite"
        );
    }

    #[test]
    fn psk_mode_rejects_certificate_suites() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let ctx = CryptoContext::new(AuthMode::Psk, config);

        for suite in Dtls12CipherSuite::supported() {
            if !suite.is_psk() {
                assert!(
                    !ctx.is_cipher_suite_compatible(*suite),
                    "PSK-mode context must reject certificate suite {:?}",
                    suite
                );
            }
        }
    }

    #[test]
    fn psk_mode_accepts_psk_suites() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let ctx = CryptoContext::new(AuthMode::Psk, config);

        assert!(
            Dtls12CipherSuite::supported()
                .iter()
                .filter(|s| s.is_psk())
                .any(|s| ctx.is_cipher_suite_compatible(*s)),
            "PSK-mode context must accept at least one PSK suite"
        );
    }

    #[test]
    fn prf_workspaces_are_cleared_on_success_and_failure() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let mut ctx = CryptoContext::new(AuthMode::Psk, Arc::clone(&config));
        let mut out = vec![0xA5; 64].to_buf();
        let mut scratch = vec![0x5A; 64].to_buf();

        let error = ctx
            .derive_extended_master_secret(
                &[0x11; 32],
                HashAlgorithm::SHA256,
                &mut out,
                &mut scratch,
            )
            .expect_err("missing pre-master secret must fail");
        assert_eq!(error, CryptoError::PreMasterSecretNotAvailable);
        assert!(out.is_empty());
        assert!(scratch.is_empty());

        ctx.set_psk(vec![0x22; 16]);
        ctx.compute_psk_pre_master_secret()
            .expect("compute PSK pre-master secret");
        out.extend_from_slice(&[0xA5; 64]);
        scratch.extend_from_slice(&[0x5A; 64]);
        ctx.derive_extended_master_secret(
            &[0x33; 32],
            HashAlgorithm::SHA256,
            &mut out,
            &mut scratch,
        )
        .expect("derive master secret");
        assert!(out.is_empty());
        assert!(scratch.is_empty());
        assert!(ctx.master_secret.is_some());
    }

    #[test]
    fn explicit_secret_cleanup_removes_all_dtls12_key_material() {
        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let mut ctx = CryptoContext::new(AuthMode::Psk, config);
        ctx.client_write_key = Some(vec![0x11; 16].to_buf());
        ctx.server_write_key = Some(vec![0x22; 16].to_buf());
        ctx.client_mac_key = Some(vec![0x33; 32].to_buf());
        ctx.server_mac_key = Some(vec![0x44; 32].to_buf());
        ctx.pre_master_secret = Some(vec![0x55; 48].to_buf());
        ctx.psk = Some(vec![0x66; 16]);
        ctx.client_write_iv = Some(Iv::new(&[0x77; 4]).expect("client IV"));
        ctx.server_write_iv = Some(Iv::new(&[0x88; 4]).expect("server IV"));
        let mut master_secret = ArrayVec::new();
        master_secret
            .try_extend_from_slice(&[0x99; 48])
            .expect("master secret fits");
        ctx.master_secret = Some(master_secret);

        ctx.zeroize_secrets();

        assert!(ctx.client_write_key.is_none());
        assert!(ctx.server_write_key.is_none());
        assert!(ctx.client_mac_key.is_none());
        assert!(ctx.server_mac_key.is_none());
        assert!(ctx.pre_master_secret.is_none());
        assert!(ctx.psk.is_none());
        assert!(ctx.client_write_iv.is_none());
        assert!(ctx.server_write_iv.is_none());
        assert!(ctx.master_secret.is_none());
    }

    #[test]
    fn rfc6083_exporter_matches_independent_rfc5705_vector() {
        // Expected output was generated independently with Python's
        // hmac/hashlib implementation of the RFC 5246 P_SHA256 recurrence:
        //
        // secret        = 00..2f
        // client_random = 20..3f
        // server_random = a0..bf
        // label         = EXPORTER_DTLS_OVER_SCTP
        const EXPECTED: [u8; 64] = [
            0xba, 0x69, 0x77, 0x55, 0x69, 0x00, 0x44, 0xf1, 0x09, 0x19, 0x75, 0x85, 0x46, 0x86,
            0x4a, 0xb9, 0xa6, 0x11, 0x14, 0x55, 0x5a, 0x56, 0x81, 0xa9, 0xb5, 0xe2, 0x0c, 0x38,
            0x6d, 0xdf, 0x31, 0xaf, 0xd5, 0x86, 0x64, 0xd4, 0x56, 0xfd, 0xc5, 0x62, 0x38, 0x17,
            0x7d, 0x1f, 0x35, 0x80, 0x53, 0x65, 0x0e, 0xb4, 0x74, 0x23, 0x6b, 0x8b, 0x77, 0xc1,
            0xe7, 0x80, 0xa8, 0xe0, 0x7f, 0x30, 0xa7, 0x6c,
        ];

        let config = Arc::new(Config::builder().build().expect("valid default config"));
        let mut ctx = CryptoContext::new(AuthMode::Psk, config);

        let master_secret_bytes: [u8; 48] = core::array::from_fn(|index| index as u8);
        let mut master_secret = ArrayVec::new();
        master_secret
            .try_extend_from_slice(&master_secret_bytes)
            .expect("48-byte master secret fits");
        ctx.master_secret = Some(master_secret);

        let client_random_bytes: [u8; 32] = core::array::from_fn(|index| 0x20_u8 + index as u8);
        let mut client_random = ArrayVec::new();
        client_random
            .try_extend_from_slice(&client_random_bytes)
            .expect("32-byte client random fits");
        ctx.client_random = Some(client_random);

        let server_random_bytes: [u8; 32] = core::array::from_fn(|index| 0xa0_u8 + index as u8);
        let mut server_random = ArrayVec::new();
        server_random
            .try_extend_from_slice(&server_random_bytes)
            .expect("32-byte server random fits");
        ctx.server_random = Some(server_random);

        let mut out = Buf::new();
        let mut scratch = Buf::new();
        let material = ctx
            .extract_rfc6083_keying_material(HashAlgorithm::SHA256, &mut out, &mut scratch)
            .expect("RFC 5705 exporter");

        assert_eq!(material.as_slice(), EXPECTED);
    }
}
