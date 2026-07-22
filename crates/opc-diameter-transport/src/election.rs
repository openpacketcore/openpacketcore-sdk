//! Transport-generic RFC 6733 simultaneous-open election.
//!
//! When both Diameter peers establish a connection at the same time, each
//! endpoint temporarily owns an initiated connection and a responder
//! connection. RFC 6733 section 5.6.4 elects a winner by comparing the local
//! and received Origin-Host values as ASCII octet streams. The winner closes
//! the connection it initiated, causing both peers to retain the same
//! connection.

use core::{cmp::Ordering, fmt};

/// Validated identities for one RFC 6733 simultaneous-open election.
///
/// The local value is the responder's configured Origin-Host. The peer value
/// is the Origin-Host received in the CER on the responder connection. Values
/// are required to be nonempty ASCII, matching the shared Diameter identity
/// contract; this type deliberately does not impose a narrower DNS grammar.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiameterElectionInput<'a> {
    local_origin_host: &'a str,
    peer_origin_host: &'a str,
}

impl<'a> DiameterElectionInput<'a> {
    /// Validate the local and received peer Origin-Host values.
    pub fn new(
        local_origin_host: &'a str,
        peer_origin_host: &'a str,
    ) -> Result<Self, DiameterElectionError> {
        validate_origin_host(local_origin_host, ElectionIdentity::Local)?;
        validate_origin_host(peer_origin_host, ElectionIdentity::Peer)?;

        Ok(Self {
            local_origin_host,
            peer_origin_host,
        })
    }
}

impl fmt::Debug for DiameterElectionInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterElectionInput([redacted])")
    }
}

/// Connection that survives a completed simultaneous-open election.
///
/// The variants are expressed from the local endpoint's perspective. They
/// also encode the election winner without permitting an inconsistent
/// winner/survivor pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiameterElectionOutcome {
    /// The peer won; retain the locally initiated connection and close the
    /// locally accepted responder connection.
    KeepInitiatedConnection,
    /// The local endpoint won; retain the locally accepted responder
    /// connection and close the connection the local endpoint initiated.
    KeepResponderConnection,
}

impl DiameterElectionOutcome {
    /// Return whether the local endpoint won the RFC 6733 election.
    #[must_use]
    pub const fn local_won(self) -> bool {
        matches!(self, Self::KeepResponderConnection)
    }
}

/// Stable, redaction-safe simultaneous-open election failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiameterElectionError {
    /// The configured local Origin-Host is empty.
    EmptyLocalOriginHost,
    /// The received peer Origin-Host is empty.
    EmptyPeerOriginHost,
    /// The configured local Origin-Host contains a non-ASCII code point.
    NonAsciiLocalOriginHost,
    /// The received peer Origin-Host contains a non-ASCII code point.
    NonAsciiPeerOriginHost,
    /// The identities compare equally under RFC 6733 ASCII case folding, so
    /// neither candidate can be selected safely.
    IndistinguishableOriginHosts,
}

impl DiameterElectionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyLocalOriginHost => "diameter_election_local_origin_host_empty",
            Self::EmptyPeerOriginHost => "diameter_election_peer_origin_host_empty",
            Self::NonAsciiLocalOriginHost => "diameter_election_local_origin_host_non_ascii",
            Self::NonAsciiPeerOriginHost => "diameter_election_peer_origin_host_non_ascii",
            Self::IndistinguishableOriginHosts => {
                "diameter_election_origin_hosts_indistinguishable"
            }
        }
    }
}

impl fmt::Display for DiameterElectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyLocalOriginHost => "local Diameter Origin-Host is empty",
            Self::EmptyPeerOriginHost => "peer Diameter Origin-Host is empty",
            Self::NonAsciiLocalOriginHost => "local Diameter Origin-Host is not ASCII",
            Self::NonAsciiPeerOriginHost => "peer Diameter Origin-Host is not ASCII",
            Self::IndistinguishableOriginHosts => {
                "Diameter simultaneous-open identities are indistinguishable"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DiameterElectionError {}

/// Resolve an RFC 6733 section 5.6.4 simultaneous-open race.
///
/// ASCII letters compare case-insensitively; all other ASCII octets retain
/// their ordinary lexicographic order. If both Origin-Host values compare
/// equally, the function fails closed. The caller must close both candidates
/// rather than transition either connection to the open state.
pub fn elect_simultaneous_open(
    input: DiameterElectionInput<'_>,
) -> Result<DiameterElectionOutcome, DiameterElectionError> {
    match compare_origin_hosts(input.local_origin_host, input.peer_origin_host) {
        Ordering::Less => Ok(DiameterElectionOutcome::KeepInitiatedConnection),
        Ordering::Greater => Ok(DiameterElectionOutcome::KeepResponderConnection),
        Ordering::Equal => Err(DiameterElectionError::IndistinguishableOriginHosts),
    }
}

#[derive(Clone, Copy)]
enum ElectionIdentity {
    Local,
    Peer,
}

fn validate_origin_host(
    origin_host: &str,
    identity: ElectionIdentity,
) -> Result<(), DiameterElectionError> {
    if origin_host.is_empty() {
        return Err(match identity {
            ElectionIdentity::Local => DiameterElectionError::EmptyLocalOriginHost,
            ElectionIdentity::Peer => DiameterElectionError::EmptyPeerOriginHost,
        });
    }
    if !origin_host.is_ascii() {
        return Err(match identity {
            ElectionIdentity::Local => DiameterElectionError::NonAsciiLocalOriginHost,
            ElectionIdentity::Peer => DiameterElectionError::NonAsciiPeerOriginHost,
        });
    }
    Ok(())
}

fn compare_origin_hosts(local_origin_host: &str, peer_origin_host: &str) -> Ordering {
    local_origin_host
        .bytes()
        .map(|octet| octet.to_ascii_uppercase())
        .cmp(
            peer_origin_host
                .bytes()
                .map(|octet| octet.to_ascii_uppercase()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn election(
        local_origin_host: &str,
        peer_origin_host: &str,
    ) -> Result<DiameterElectionOutcome, DiameterElectionError> {
        let input = DiameterElectionInput::new(local_origin_host, peer_origin_host)?;
        elect_simultaneous_open(input)
    }

    #[test]
    fn lexicographically_lesser_local_identity_keeps_initiated_connection() {
        assert_eq!(
            election("aaa.example.net", "bbb.example.net"),
            Ok(DiameterElectionOutcome::KeepInitiatedConnection)
        );
    }

    #[test]
    fn lexicographically_greater_local_identity_keeps_responder_connection() {
        assert_eq!(
            election("bbb.example.net", "aaa.example.net"),
            Ok(DiameterElectionOutcome::KeepResponderConnection)
        );
    }

    #[test]
    fn opposite_responder_views_converge_on_one_connection() {
        let lower = election("aaa.example.net", "bbb.example.net");
        let higher = election("bbb.example.net", "aaa.example.net");

        assert_eq!(lower, Ok(DiameterElectionOutcome::KeepInitiatedConnection));
        assert_eq!(higher, Ok(DiameterElectionOutcome::KeepResponderConnection));
    }

    #[test]
    fn comparison_is_ascii_case_insensitive_at_every_position() {
        assert_eq!(
            election("node-a.example.net", "NODE-B.EXAMPLE.NET"),
            Ok(DiameterElectionOutcome::KeepInitiatedConnection)
        );
        assert_eq!(
            election("NODE-B.EXAMPLE.NET", "node-a.example.net"),
            Ok(DiameterElectionOutcome::KeepResponderConnection)
        );
    }

    #[test]
    fn identical_and_case_only_equal_identities_fail_closed() {
        assert_eq!(
            election("node.example.net", "node.example.net"),
            Err(DiameterElectionError::IndistinguishableOriginHosts)
        );
        assert_eq!(
            election("node.example.net", "NODE.EXAMPLE.NET"),
            Err(DiameterElectionError::IndistinguishableOriginHosts)
        );
    }

    #[test]
    fn comparison_uses_octet_stream_prefix_ordering() {
        assert_eq!(
            election("node", "node.example.net"),
            Ok(DiameterElectionOutcome::KeepInitiatedConnection)
        );
        assert_eq!(
            election("node.example.net", "node"),
            Ok(DiameterElectionOutcome::KeepResponderConnection)
        );
    }

    #[test]
    fn non_letters_keep_their_ascii_octet_order() {
        assert_eq!(
            election("node-1.example.net", "node.1.example.net"),
            Ok(DiameterElectionOutcome::KeepInitiatedConnection)
        );
        assert_eq!(
            election("node:1.example.net", "node.1.example.net"),
            Ok(DiameterElectionOutcome::KeepResponderConnection)
        );
    }

    #[test]
    fn every_single_ascii_octet_pair_matches_rfc_case_folding() {
        for local in 0_u8..=0x7f {
            for peer in 0_u8..=0x7f {
                let local_origin_host = char::from(local).to_string();
                let peer_origin_host = char::from(peer).to_string();
                let actual = election(&local_origin_host, &peer_origin_host);
                let expected = match local.to_ascii_uppercase().cmp(&peer.to_ascii_uppercase()) {
                    Ordering::Less => Ok(DiameterElectionOutcome::KeepInitiatedConnection),
                    Ordering::Greater => Ok(DiameterElectionOutcome::KeepResponderConnection),
                    Ordering::Equal => Err(DiameterElectionError::IndistinguishableOriginHosts),
                };

                assert_eq!(actual, expected, "local={local:#04x}, peer={peer:#04x}");
            }
        }
    }

    #[test]
    fn invalid_identity_errors_are_specific_and_redaction_safe() {
        assert_eq!(
            DiameterElectionInput::new("", "peer.example.net"),
            Err(DiameterElectionError::EmptyLocalOriginHost)
        );
        assert_eq!(
            DiameterElectionInput::new("local.example.net", ""),
            Err(DiameterElectionError::EmptyPeerOriginHost)
        );
        assert_eq!(
            DiameterElectionInput::new("løcal.example.net", "peer.example.net"),
            Err(DiameterElectionError::NonAsciiLocalOriginHost)
        );
        assert_eq!(
            DiameterElectionInput::new("local.example.net", "péer.example.net"),
            Err(DiameterElectionError::NonAsciiPeerOriginHost)
        );

        let error = election("secret.example.net", "SECRET.EXAMPLE.NET")
            .expect_err("case-insensitive identity tie must fail closed");
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("secret.example.net"));
        assert!(!display.contains("secret.example.net"));
        assert_eq!(
            error.as_str(),
            "diameter_election_origin_hosts_indistinguishable"
        );
    }

    #[test]
    fn input_debug_redacts_both_origin_hosts() {
        let input = DiameterElectionInput::new("local.secret.net", "peer.secret.net")
            .expect("valid ASCII identities must construct an election input");
        let debug = format!("{input:?}");

        assert_eq!(debug, "DiameterElectionInput([redacted])");
        assert!(!debug.contains("local.secret.net"));
        assert!(!debug.contains("peer.secret.net"));
    }

    #[test]
    fn outcome_reports_the_local_winner_without_an_inconsistent_pair() {
        assert!(!DiameterElectionOutcome::KeepInitiatedConnection.local_won());
        assert!(DiameterElectionOutcome::KeepResponderConnection.local_won());
    }
}
