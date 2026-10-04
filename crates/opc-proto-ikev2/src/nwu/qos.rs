use super::Error;
use std::fmt;

/// One supported additional QoS parameter, using exact TS 24.502 wire units.
/// Values are validated by [`AdditionalQos::encode_parameters`]. No rate policy
/// or floating-point unit conversion is performed. Diagnostics redact contents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QosParameter<'a> {
    /// QoS characteristics (1): resource type, priority, delay, error rate, and
    /// conditional averaging window / maximum burst. Exact wire representation.
    Characteristics(&'a [u8]),
    /// MFBR downlink (2), unit followed by the big-endian value.
    MaximumDownlink([u8; 3]),
    /// MFBR uplink (3).
    MaximumUplink([u8; 3]),
    /// GFBR downlink (4).
    GuaranteedDownlink([u8; 3]),
    /// GFBR uplink (5).
    GuaranteedUplink([u8; 3]),
    /// Maximum downlink packet loss in tenths of one percent (7).
    LossDownlink(u16),
    /// Maximum uplink packet loss in tenths of one percent (8).
    LossUplink(u16),
}
impl fmt::Debug for QosParameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QosParameter([REDACTED])")
    }
}

/// Validated, borrowed additional QoS parameter list, including the count octet.
/// Unknown parameters and Notification Control (6) are discarded by iteration
/// and canonical encoding as TS 24.502 specifies. Their framing still counts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdditionalQos<'a>(&'a [u8]);
impl fmt::Debug for AdditionalQos<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdditionalQos([REDACTED])")
    }
}
impl<'a> AdditionalQos<'a> {
    /// Validate a complete list. Known duplicate parameters are rejected by
    /// this profile's local admission policy; ignored fields are still bounded.
    pub fn new(wire: &'a [u8]) -> Result<Self, Error> {
        if wire.is_empty() {
            return Err(Error::Framing);
        }
        if wire.len() > 252 {
            return Err(Error::Limit);
        }
        let mut rest = &wire[1..];
        let mut seen = 0u16;
        let mut non_gbr = false;
        for _ in 0..wire[0] {
            let (&[id, len], tail) = rest.split_first_chunk::<2>().ok_or(Error::Framing)?;
            let data = tail.get(..usize::from(len)).ok_or(Error::Framing)?;
            if let Some(parsed) = parameter(id, data)? {
                if let QosParameter::Characteristics(value) = parsed {
                    non_gbr = value[0] == 2;
                }
                let bit = 1u16 << id;
                if seen & bit != 0 {
                    return Err(Error::Duplicate);
                }
                seen |= bit;
            }
            rest = &tail[usize::from(len)..];
        }
        if !rest.is_empty() {
            return Err(Error::Framing);
        }
        if non_gbr && seen & !2 != 0 {
            return Err(Error::Incompatible);
        }
        Ok(Self(wire))
    }
    /// Iterate supported parameters. Validation has already checked every entry.
    pub fn parameters(self) -> impl Iterator<Item = QosParameter<'a>> {
        let mut rest = &self.0[1..];
        std::iter::from_fn(move || {
            while let Some((&[id, len], tail)) = rest.split_first_chunk::<2>() {
                let data = tail.get(..usize::from(len))?;
                rest = &tail[usize::from(len)..];
                if let Ok(Some(p)) = parameter(id, data) {
                    return Some(p);
                }
            }
            None
        })
    }
    /// Build a bounded list of supported parameters. A full QoS envelope can
    /// impose a smaller remaining budget after its QFI list and optional DSCP.
    pub fn encode_parameters(parameters: &[QosParameter<'_>]) -> Result<Vec<u8>, Error> {
        if parameters.len() > 7 {
            return Err(Error::Limit);
        }
        let mut out = vec![parameters.len() as u8];
        for p in parameters {
            match *p {
                QosParameter::Characteristics(data) => {
                    if data.len() > 10 {
                        return Err(Error::InvalidValue);
                    }
                    out.extend_from_slice(&[1, data.len() as u8]);
                    out.extend_from_slice(data);
                }
                QosParameter::MaximumDownlink(data)
                | QosParameter::MaximumUplink(data)
                | QosParameter::GuaranteedDownlink(data)
                | QosParameter::GuaranteedUplink(data) => {
                    let id = match p {
                        QosParameter::MaximumDownlink(_) => 2,
                        QosParameter::MaximumUplink(_) => 3,
                        QosParameter::GuaranteedDownlink(_) => 4,
                        _ => 5,
                    };
                    out.extend_from_slice(&[id, 3]);
                    out.extend_from_slice(&data);
                }
                QosParameter::LossDownlink(value) | QosParameter::LossUplink(value) => {
                    out.extend_from_slice(&[
                        if matches!(p, QosParameter::LossDownlink(_)) {
                            7
                        } else {
                            8
                        },
                        2,
                    ]);
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
        }
        Self::validate_owned(&out)?;
        Ok(out)
    }
    fn validate_owned(wire: &[u8]) -> Result<(), Error> {
        AdditionalQos::new(wire).map(|_| ())
    }
    fn encode(self) -> Result<Vec<u8>, Error> {
        Self::encode_parameters(&self.parameters().collect::<Vec<_>>())
    }
}

fn parameter(id: u8, data: &[u8]) -> Result<Option<QosParameter<'_>>, Error> {
    Ok(Some(match id {
        1 => {
            let first = *data.first().ok_or(Error::InvalidValue)?;
            let len = match first {
                0 => 8,
                1 => 10,
                2 => 6,
                _ => return Err(Error::Unsupported),
            };
            if data.len() != len
                || !(1..=127).contains(&data[1])
                || u16::from_be_bytes([data[2], data[3]]) > 1023
                || data[4] > 9
                || data[5] > 9
                || (len >= 8 && u16::from_be_bytes([data[6], data[7]]) > 4095)
                || (len == 10 && u16::from_be_bytes([data[8], data[9]]) > 4095)
            {
                return Err(Error::InvalidValue);
            }
            QosParameter::Characteristics(data)
        }
        2..=5 => {
            // Unit codes above 25 retain their wire value; receivers interpret
            // them as 256 Pbps per table 9.3.1.1-2, rather than rejecting them.
            let value = data.try_into().map_err(|_| Error::InvalidValue)?;
            match id {
                2 => QosParameter::MaximumDownlink(value),
                3 => QosParameter::MaximumUplink(value),
                4 => QosParameter::GuaranteedDownlink(value),
                _ => QosParameter::GuaranteedUplink(value),
            }
        }
        7 | 8 => {
            let value = u16::from_be_bytes(data.try_into().map_err(|_| Error::InvalidValue)?);
            if value > 1000 {
                return Err(Error::InvalidValue);
            }
            if id == 7 {
                QosParameter::LossDownlink(value)
            } else {
                QosParameter::LossUplink(value)
            }
        }
        _ => return Ok(None),
    }))
}

/// Complete QoS flow association from a 5G_QOS_INFO Notify.
/// Applying a modification replaces the previous association; this value is
/// never a delta. Reserved QFI and flag bits are ignored on receive and cleared
/// by canonical encoding. Duplicate QFIs are rejected by local admission policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosInfo<'a> {
    session: u8,
    qfis: &'a [u8],
    default: bool,
    dscp: Option<u8>,
    additional: Option<AdditionalQos<'a>>,
}
impl fmt::Debug for QosInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QosInfo")
            .field("qfi_count", &self.qfis.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}
impl<'a> QosInfo<'a> {
    /// Construct a canonical association. Session IDs are 1..=15; QFIs 1..=63.
    /// An empty QFI list is supported. DSCP is an unshifted six-bit value.
    pub fn new(
        session: u8,
        qfis: &'a [u8],
        default: bool,
        dscp: Option<u8>,
        additional: Option<AdditionalQos<'a>>,
    ) -> Result<Self, Error> {
        if qfis.iter().any(|q| *q > 63) || dscp.is_some_and(|v| v > 63) {
            return Err(Error::InvalidValue);
        }
        let value = Self {
            session,
            qfis,
            default,
            dscp,
            additional,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<(), Error> {
        if !(1..=15).contains(&self.session) {
            return Err(Error::InvalidValue);
        }
        let mut seen = 0u64;
        for qfi in self.qfis() {
            if qfi == 0 {
                return Err(Error::InvalidValue);
            }
            let bit = 1u64 << qfi;
            if seen & bit != 0 {
                return Err(Error::Duplicate);
            }
            seen |= bit;
        }
        // Include all received extension bytes, even those later discarded.
        let len = 3
            + self.qfis.len()
            + usize::from(self.dscp.is_some())
            + self.additional.map_or(0, |v| v.0.len());
        if len > 255 {
            return Err(Error::Limit);
        }
        Ok(())
    }
    /// Decode notification data (starting with the one-octet Length field).
    pub fn decode(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 4 || usize::from(data[0]) != data.len() - 1 {
            return Err(Error::Framing);
        }
        let count = usize::from(data[2]);
        let qfis = data.get(3..3 + count).ok_or(Error::Framing)?;
        let flags = *data.get(3 + count).ok_or(Error::Framing)?;
        let mut rest = &data[4 + count..];
        let dscp = if flags & 1 != 0 {
            let (&value, tail) = rest.split_first().ok_or(Error::Framing)?;
            rest = tail;
            if value > 63 {
                return Err(Error::InvalidValue);
            }
            Some(value)
        } else {
            None
        };
        let additional = if flags & 4 != 0 {
            Some(AdditionalQos::new(rest)?)
        } else {
            if !rest.is_empty() {
                return Err(Error::Framing);
            }
            None
        };
        let value = Self {
            session: data[1],
            qfis,
            default: flags & 2 != 0,
            dscp,
            additional,
        };
        value.validate()?;
        Ok(value)
    }
    /// Explicit access to the session identifier.
    pub const fn session(self) -> u8 {
        self.session
    }
    /// Canonical QFI values, with the two reserved bits removed.
    pub fn qfis(self) -> impl ExactSizeIterator<Item = u8> + 'a {
        self.qfis.iter().map(|v| v & 0x3f)
    }
    /// Whether this SA is the PDU session's default SA. Roster uniqueness is caller-owned.
    pub const fn is_default(self) -> bool {
        self.default
    }
    /// Optional unshifted DSCP.
    pub const fn dscp(self) -> Option<u8> {
        self.dscp
    }
    /// Optional additional QoS information.
    pub const fn additional(self) -> Option<AdditionalQos<'a>> {
        self.additional
    }
    /// Encode the complete association with zero reserved bits.
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let extra = self.additional.map(AdditionalQos::encode).transpose()?;
        let len = 3
            + self.qfis.len()
            + usize::from(self.dscp.is_some())
            + extra.as_ref().map_or(0, Vec::len);
        let mut out = Vec::with_capacity(1 + len);
        out.extend_from_slice(&[len as u8, self.session, self.qfis.len() as u8]);
        out.extend(self.qfis());
        out.push(
            u8::from(self.dscp.is_some())
                | (u8::from(self.default) << 1)
                | (u8::from(extra.is_some()) << 2),
        );
        if let Some(dscp) = self.dscp {
            out.push(dscp);
        }
        if let Some(extra) = extra {
            out.extend(extra);
        }
        Ok(out)
    }
}
