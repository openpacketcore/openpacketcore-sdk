//! Bounded N3IWF PSC helpers shared by host tests and the native classifier.

/// Size of the optional GTP-U block followed by one uplink PSC.
pub const N3_UPLINK_EXTENSION_LEN: usize = 8;

/// Construct the single-QFI uplink PSC and its preceding optional field block.
///
/// Sequence and N-PDU fields are zero. This does not construct the mandatory
/// GTP-U header, which must set E and account for these eight bytes in length.
/// QFI is not truncated, and no RQI/PPI or delay-reporting fields are generated.
#[must_use]
pub const fn n3_uplink_extension(qfi: u8) -> Option<[u8; N3_UPLINK_EXTENSION_LEN]> {
    if qfi > 63 {
        return None;
    }
    Some([0, 0, 0, 0x85, 1, 0x10, qfi, 0])
}

/// Check the fixed-flow downlink PSC against one installed QFI.
///
/// `prefix` is length-in-four-octets, PDU-type/flags, and QFI/RQI/PPP.
/// The caller must first validate the complete extension, next-header chain,
/// exact envelope and single-PSC cardinality. RQI/PPI are accepted as metadata
/// and do not select another mark, peer, or authority. Spare bits are ignored
/// exactly as in the shared protocol decoder. Unmodelled conditionals fail
/// closed. This is the TS 38.415 QFI/RQI/PPI subset, not the complete protocol.
#[must_use]
pub const fn n3_downlink_psc_matches(prefix: [u8; 3], qfi: u8) -> bool {
    qfi <= 63
        && prefix[1] >> 4 == 0
        && prefix[1] & 0x0e == 0
        && prefix[2] & 0x3f == qfi
        && if prefix[2] & 0x80 == 0 {
            prefix[0] == 1
        } else {
            prefix[0] == 2
        }
}
