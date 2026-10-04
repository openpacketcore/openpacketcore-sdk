use super::{CreateRequest, Error, EspSpi};
use crate::{
    Ikev2ChildSaCryptoProfile, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2PrfAlgorithm,
    Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue,
};

/// One caller-selected AEAD ESP suite. This optional policy boundary provides
/// no default list and does not change generic IKE/ESP algorithm support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadSuite {
    encryption: Ikev2EncryptionAlgorithm,
    dh: Option<Ikev2DhGroup>,
    esn: bool,
}
impl AeadSuite {
    /// Require combined-mode encryption with no separate integrity algorithm.
    /// DH group and ESN policy are explicit; neither is silently substituted.
    pub fn new(
        encryption: Ikev2EncryptionAlgorithm,
        dh: Option<Ikev2DhGroup>,
        esn: bool,
    ) -> Result<Self, Error> {
        if !encryption.is_aead() {
            return Err(Error::Incompatible);
        }
        Ok(Self {
            encryption,
            dh,
            esn,
        })
    }
    /// Selected encryption capability.
    pub const fn encryption(self) -> Ikev2EncryptionAlgorithm {
        self.encryption
    }
    /// Selected optional PFS group.
    pub const fn dh_group(self) -> Option<Ikev2DhGroup> {
        self.dh
    }
    /// Whether extended sequence numbers are selected.
    pub const fn extended_sequence_numbers(self) -> bool {
        self.esn
    }
    /// Existing Child-SA KEYMAT profile, with PRF inherited from the IKE SA.
    pub const fn crypto_profile(self, prf: Ikev2PrfAlgorithm) -> Ikev2ChildSaCryptoProfile {
        Ikev2ChildSaCryptoProfile::new_aead(prf, self.encryption)
    }
    fn transforms(self) -> Vec<Ikev2SaTransformBuild> {
        let mut out = vec![Ikev2SaTransformBuild {
            transform_type: 1,
            transform_id: self.encryption.transform_id(),
            attributes: vec![Ikev2TransformAttributeBuild {
                attribute_type: 14,
                value: Ikev2TransformAttributeBuildValue::Tv(self.encryption.key_bits()),
            }],
        }];
        if let Some(dh) = self.dh {
            out.push(Ikev2SaTransformBuild {
                transform_type: 4,
                transform_id: dh.transform_id(),
                attributes: vec![],
            });
        }
        out.push(Ikev2SaTransformBuild {
            transform_type: 5,
            transform_id: u16::from(self.esn),
            attributes: vec![],
        });
        out
    }
}
/// Strict caller-order ESP selection. No implicit suite, integrity transform,
/// or fallback is added. Selection has no crypto, key, SPI-allocation or backend
/// operation effects; it produces intent for those separate boundaries.
#[derive(Debug, Clone)]
pub struct AeadPolicy {
    preferred: Vec<AeadSuite>,
}
impl AeadPolicy {
    /// Configure most-preferred first; reject empty or duplicated suites.
    pub fn new(preferred: Vec<AeadSuite>) -> Result<Self, Error> {
        if preferred.is_empty() {
            return Err(Error::Missing);
        }
        if preferred.len() > 128 {
            return Err(Error::Limit);
        }
        for (i, v) in preferred.iter().enumerate() {
            if preferred[..i].contains(v) {
                return Err(Error::Duplicate);
            }
        }
        Ok(Self { preferred })
    }
    /// Try caller suite order before peer proposal order. A preferred DH group
    /// must match the supplied KE and its exact public-value size. Disjoint or
    /// non-AEAD-only offers fail without producing negotiation intent.
    pub fn select(&self, request: &CreateRequest<'_>) -> Result<AeadSelection, Error> {
        for suite in self.preferred.iter().copied() {
            for p in &request.security_association().proposals {
                if p.transforms.iter().any(|t| t.transform_type == 3) {
                    continue;
                }
                let encryption = p.transforms.iter().any(|t| {
                    t.transform_type == 1
                        && Ikev2EncryptionAlgorithm::from_sa_transform(t) == Ok(suite.encryption)
                });
                let esn = p
                    .transforms
                    .iter()
                    .any(|t| t.transform_type == 5 && t.transform_id == u16::from(suite.esn));
                let dh = match suite.dh {
                    Some(group) => p
                        .transforms
                        .iter()
                        .any(|t| t.transform_type == 4 && t.transform_id == group.transform_id()),
                    None => {
                        !p.transforms.iter().any(|t| t.transform_type == 4)
                            || p.transforms
                                .iter()
                                .any(|t| t.transform_type == 4 && t.transform_id == 0)
                    }
                };
                if !encryption || !esn || !dh {
                    continue;
                }
                if let Some(group) = suite.dh {
                    let Some(ke) = request.key_exchange() else {
                        continue;
                    };
                    if ke.dh_group != group.transform_id() {
                        continue;
                    }
                    if ke.key_exchange_data.len() != group.public_value_len() {
                        return Err(Error::InvalidValue);
                    }
                }
                return Ok(AeadSelection {
                    suite,
                    proposal_number: p.proposal_number,
                    peer_spi: EspSpi::new(p.spi.try_into().map_err(|_| Error::SpiShape)?)?,
                });
            }
        }
        Err(Error::Incompatible)
    }
}
/// Selected suite and peer inbound SPI, before any operation or key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadSelection {
    suite: AeadSuite,
    proposal_number: u8,
    peer_spi: EspSpi,
}
impl AeadSelection {
    /// Chosen caller suite.
    pub const fn suite(self) -> AeadSuite {
        self.suite
    }
    /// Sender-owned inbound SPI from the offered proposal.
    pub const fn peer_spi(self) -> EspSpi {
        self.peer_spi
    }
    /// Construct the response SA using a separately allocated local inbound SPI.
    pub fn response_sa(self, local_spi: EspSpi) -> Ikev2SaPayloadBuild {
        Ikev2SaPayloadBuild {
            proposals: vec![Ikev2SaProposalBuild {
                proposal_number: self.proposal_number,
                protocol_id: 3,
                spi: local_spi.octets().to_vec(),
                transforms: self.suite.transforms(),
            }],
        }
    }
}
