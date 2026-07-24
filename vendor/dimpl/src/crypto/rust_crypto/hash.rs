//! Hash implementations using RustCrypto.

use sha2::{Digest, Sha256, Sha384};

use super::super::{HashContext, HashProvider};
use crate::buffer::Buf;
use crate::types::HashAlgorithm;

/// Hash context implementation using RustCrypto.
enum RustCryptoHashContext {
    Sha256(Sha256),
    Sha384(Sha384),
    Unsupported,
}

impl std::fmt::Debug for RustCryptoHashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RustCryptoHashContext::Sha256(_) => {
                f.debug_tuple("RustCryptoHashContext::Sha256").finish()
            }
            RustCryptoHashContext::Sha384(_) => {
                f.debug_tuple("RustCryptoHashContext::Sha384").finish()
            }
            RustCryptoHashContext::Unsupported => f.write_str("RustCryptoHashContext::Unsupported"),
        }
    }
}

impl HashContext for RustCryptoHashContext {
    fn update(&mut self, data: &[u8]) {
        match self {
            RustCryptoHashContext::Sha256(ctx) => ctx.update(data),
            RustCryptoHashContext::Sha384(ctx) => ctx.update(data),
            RustCryptoHashContext::Unsupported => {}
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        match self {
            RustCryptoHashContext::Sha256(ctx) => {
                let cloned = ctx.clone();
                let digest = cloned.finalize();
                out.clear();
                out.extend_from_slice(&digest);
            }
            RustCryptoHashContext::Sha384(ctx) => {
                let cloned = ctx.clone();
                let digest = cloned.finalize();
                out.clear();
                out.extend_from_slice(&digest);
            }
            RustCryptoHashContext::Unsupported => out.clear(),
        }
    }
}

/// Hash provider implementation.
#[derive(Debug)]
pub(super) struct RustCryptoHashProvider;

impl HashProvider for RustCryptoHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(RustCryptoHashContext::Sha256(Sha256::new())),
            HashAlgorithm::SHA384 => Box::new(RustCryptoHashContext::Sha384(Sha384::new())),
            _ => Box::new(RustCryptoHashContext::Unsupported),
        }
    }
}

/// Static instance of the hash provider.
pub(super) static HASH_PROVIDER: RustCryptoHashProvider = RustCryptoHashProvider;
