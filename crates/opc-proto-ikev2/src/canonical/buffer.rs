use super::Ikev2CanonicalError as Error;
use zeroize::{Zeroize, Zeroizing};

// Fixed capacity for every qualified recipe. Only verified wire lengths enter
// the cache; the full backing array is wiped, including its unused tail.
#[derive(Clone)]
pub(super) struct CanonicalBytes {
    pub(super) storage: Zeroizing<[u8; 96]>,
    pub(super) len: u8,
}
impl CanonicalBytes {
    pub(super) fn from_verified(packet: &[u8]) -> Result<Self, Error> {
        if ![57, 76, 80, 88, 96].contains(&packet.len()) {
            return Err(Error::InvalidOutput);
        }
        let mut storage = Zeroizing::new([0; 96]);
        storage[..packet.len()].copy_from_slice(packet);
        Ok(Self {
            storage,
            len: packet.len() as u8,
        })
    }
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.storage[..usize::from(self.len)]
    }
    fn wipe(&mut self) {
        self.storage.zeroize();
        self.len = 0;
    }
}
impl Drop for CanonicalBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_storage_rejects_unknown_lengths_and_wipes_all_96_octets() -> Result<(), Error> {
        for len in 0..=128 {
            let input = vec![0xa5; len];
            let output = CanonicalBytes::from_verified(&input);
            if ![57, 76, 80, 88, 96].contains(&len) {
                assert!(matches!(output, Err(Error::InvalidOutput)));
                continue;
            }
            let mut bytes = output?;
            assert_eq!(bytes.as_slice(), input);
            assert_eq!(bytes.storage[len..], vec![0; 96 - len]);
            let copy = bytes.clone();
            // The same routine is called by Drop. Poison the unused tail too,
            // so wiping only the advertised wire length would fail this test.
            bytes.storage.fill(0x5a);
            bytes.wipe();
            assert!(bytes.as_slice().is_empty());
            assert_eq!(*bytes.storage, [0; 96]);
            assert_eq!(copy.as_slice(), input);
        }
        Ok(())
    }
}
