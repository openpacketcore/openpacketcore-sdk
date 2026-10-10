//! Checked slices for bounded scan envelopes, before any owned allocation.

use super::ScopeScanWireError;

pub(crate) struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, ScopeScanWireError> {
        if bytes.len() > maximum {
            return Err(ScopeScanWireError);
        }
        Ok(Self { remaining: bytes })
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], ScopeScanWireError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or(ScopeScanWireError)?;
        self.remaining = remaining;
        Ok(value)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ScopeScanWireError> {
        self.take(N)?.try_into().map_err(|_| ScopeScanWireError)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, ScopeScanWireError> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, ScopeScanWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, ScopeScanWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, ScopeScanWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn boolean(&mut self) -> Result<bool, ScopeScanWireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ScopeScanWireError),
        }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.remaining.len()
    }
    pub(crate) fn bytes_u16(&mut self, maximum: usize) -> Result<&'a [u8], ScopeScanWireError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(ScopeScanWireError);
        }
        self.take(count)
    }
    pub(crate) fn bytes_u32(&mut self, maximum: usize) -> Result<&'a [u8], ScopeScanWireError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(ScopeScanWireError);
        }
        self.take(count)
    }
    pub(crate) fn finish(self) -> Result<(), ScopeScanWireError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ScopeScanWireError)
        }
    }
}

pub(crate) struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Writer {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }
    pub(crate) fn put(&mut self, value: &[u8]) -> Result<(), ScopeScanWireError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(ScopeScanWireError)?;
        if next > self.maximum {
            return Err(ScopeScanWireError);
        }
        if next > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .max(256)
                .saturating_mul(2)
                .min(self.maximum)
                .max(next);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| ScopeScanWireError)?;
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub(crate) fn u8(&mut self, value: u8) -> Result<(), ScopeScanWireError> {
        self.put(&[value])
    }
    pub(crate) fn u16(&mut self, value: u16) -> Result<(), ScopeScanWireError> {
        self.put(&value.to_be_bytes())
    }
    pub(crate) fn u64(&mut self, value: u64) -> Result<(), ScopeScanWireError> {
        self.put(&value.to_be_bytes())
    }
    pub(crate) fn bytes_u16(
        &mut self,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), ScopeScanWireError> {
        if value.len() > maximum {
            return Err(ScopeScanWireError);
        }
        self.u16(u16::try_from(value.len()).map_err(|_| ScopeScanWireError)?)?;
        self.put(value)
    }
    pub(crate) fn bytes_u32(
        &mut self,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), ScopeScanWireError> {
        if value.len() > maximum {
            return Err(ScopeScanWireError);
        }
        self.put(
            &u32::try_from(value.len())
                .map_err(|_| ScopeScanWireError)?
                .to_be_bytes(),
        )?;
        self.put(value)
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
