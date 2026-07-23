//! Shared, fail-closed input-bound limits for the OpenPacketCore management
//! plane (gNMI and NETCONF servers).
//!
//! `opc_runtime::ResourceBudget` carries an advisory `max_request_body_bytes`,
//! but the runtime does **not** enforce it on sockets — the management plane is
//! responsible for bounding its own input. Both the gNMI and NETCONF servers use
//! the single [`MgmtLimits`] struct here so that the requirement "no protocol
//! parser accepts unbounded input" is enforced identically on both transports
//! and is centrally auditable.
//!
//! Every limit is a hard upper bound. The defaults ([`MgmtLimits::default`]) are
//! conservative production values; deployments may raise or lower them but
//! [`MgmtLimits::validate`] rejects any zero (a zero bound would either reject
//! all input or, if interpreted as "unlimited", defeat the purpose — so zero is
//! always an error, never "unbounded").
//!
//! ```
//! use opc_mgmt_limits::MgmtLimits;
//!
//! let limits = MgmtLimits::default();
//! limits.validate().expect("default limits are valid");
//!
//! // A parser checks the incoming size before allocating/decoding.
//! assert!(limits.check_request_bytes(1024).is_ok());
//! let too_big = limits.max_request_bytes + 1;
//! assert!(limits.check_request_bytes(too_big).is_err());
//! ```

#![forbid(unsafe_code)]

use std::time::Duration;

use thiserror::Error;

/// A bound that was exceeded, or a misconfigured (zero) limit.
///
/// The `Display` text names the limit and the offending magnitudes only — it
/// never carries request payload, paths, or identifiers, so it is safe to
/// surface in a client-facing error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LimitsError {
    /// An incoming quantity exceeded its configured maximum.
    #[error("management-plane limit '{limit}' exceeded: {actual} > {max}")]
    Exceeded {
        /// Stable machine-readable name of the limit (e.g. `request_bytes`).
        limit: &'static str,
        /// The configured maximum.
        max: usize,
        /// The observed value that exceeded the maximum.
        actual: usize,
    },
    /// A limit was configured as zero, which is never valid (zero is not a
    /// stand-in for "unbounded").
    #[error("management-plane limit '{limit}' must be greater than zero")]
    Zero {
        /// Stable machine-readable name of the misconfigured limit.
        limit: &'static str,
    },
    /// Two limits are mutually inconsistent (e.g. a per-value bound larger than
    /// the whole-message bound).
    #[error("management-plane limits inconsistent: {detail}")]
    Inconsistent {
        /// Human-oriented, payload-free description of the inconsistency.
        detail: &'static str,
    },
}

/// Hard upper bounds applied to all northbound management-plane input.
///
/// Fields are public for construction and inspection, but a constructed value
/// MUST pass [`MgmtLimits::validate`] before it is used to gate input. All sizes
/// are in bytes unless the field name says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MgmtLimits {
    /// Maximum size of a single decoded inbound request/message
    /// (gNMI request message; NETCONF RPC XML document).
    pub max_request_bytes: usize,
    /// Maximum number of chunks/frames that may compose one decoded inbound
    /// message. This bounds protocol framing overhead separately from payload
    /// bytes, so a valid-size message cannot be split into unbounded tiny
    /// chunks.
    pub max_frame_chunks_per_message: usize,
    /// Maximum number of paths (gNMI) or addressed nodes (NETCONF edit) in one
    /// request.
    pub max_paths_per_request: usize,
    /// Maximum size of a single encoded leaf value (gNMI `TypedValue`/JSON_IETF
    /// scalar or subtree; NETCONF XML text node).
    pub max_value_bytes: usize,
    /// Maximum nesting depth of an inbound XML document (NETCONF) or structured
    /// value (gNMI JSON). Bounds recursion in the parser.
    pub max_xml_depth: usize,
    /// Maximum number of attributes permitted on a single XML element.
    pub max_xml_attributes_per_element: usize,
    /// Maximum number of namespace declarations permitted on a single XML
    /// element.
    pub max_xml_namespace_decls: usize,
    /// Maximum conservative retained-byte charge for a single
    /// subscriber/notification queue before its lag policy
    /// (drop/disconnect/resync) engages.
    ///
    /// Protocol implementations document the charged values and fixed
    /// allocator/container overhead they exclude; this is not necessarily a
    /// strict allocator-resident-memory measurement.
    pub max_subscriber_queue_bytes: usize,
    /// Maximum number of concurrent subscriptions a single session/connection
    /// may hold.
    pub max_subscriptions_per_session: usize,
    /// Maximum number of concurrent northbound sessions/connections the server
    /// will accept.
    pub max_sessions: usize,
    /// Maximum number of subtree-filter content-match nodes (leaf text values)
    /// permitted in one `<filter>`. The server does not implement content-match
    /// semantics, but the bound still limits how many rejected nodes a client can
    /// force the parser to classify before failing closed.
    pub max_subtree_filter_content_match_nodes: usize,
    /// Maximum number of subtree-filter attribute-match nodes (element attributes)
    /// permitted in one `<filter>`. The server does not implement attribute-match
    /// semantics, but the bound still limits how many rejected nodes a client can
    /// force the parser to classify before failing closed.
    pub max_subtree_filter_attribute_match_nodes: usize,
    /// Maximum byte length of one NETCONF XPath `select` expression.
    pub max_xpath_filter_bytes: usize,
    /// Maximum number of union arms (`|` separated location paths) in one XPath
    /// filter expression.
    pub max_xpath_filter_unions: usize,
    /// Maximum total number of location-path segments evaluated across all union
    /// arms in one XPath filter expression.
    pub max_xpath_filter_segments: usize,
    /// Floor for gNMI SAMPLE sample_interval and heartbeat_interval; requests below this are rejected.
    pub min_sample_interval: std::time::Duration,
}

impl Default for MgmtLimits {
    /// Conservative production defaults. They are deliberately modest; a
    /// deployment that needs larger configs should raise them explicitly (and
    /// re-run [`MgmtLimits::validate`]) rather than discovering an implicit cap
    /// at runtime.
    fn default() -> Self {
        Self {
            max_request_bytes: 4 * 1024 * 1024,
            max_frame_chunks_per_message: 4096,
            max_paths_per_request: 1024,
            max_value_bytes: 1024 * 1024,
            max_xml_depth: 64,
            max_xml_attributes_per_element: 64,
            max_xml_namespace_decls: 64,
            max_subscriber_queue_bytes: 8 * 1024 * 1024,
            max_subscriptions_per_session: 256,
            max_sessions: 1024,
            max_subtree_filter_content_match_nodes: 16,
            max_subtree_filter_attribute_match_nodes: 16,
            max_xpath_filter_bytes: 4096,
            max_xpath_filter_unions: 32,
            max_xpath_filter_segments: 256,
            min_sample_interval: Duration::from_millis(100),
        }
    }
}

impl MgmtLimits {
    /// Validates the limit set: every field must be non-zero (fail-closed; zero
    /// is never "unbounded"), and a single value/queue may not be larger than a
    /// whole message would allow, which would make the per-value bound dead.
    pub fn validate(&self) -> Result<(), LimitsError> {
        let fields: [(&'static str, usize); 16] = [
            ("request_bytes", self.max_request_bytes),
            (
                "frame_chunks_per_message",
                self.max_frame_chunks_per_message,
            ),
            ("paths_per_request", self.max_paths_per_request),
            ("value_bytes", self.max_value_bytes),
            ("xml_depth", self.max_xml_depth),
            (
                "xml_attributes_per_element",
                self.max_xml_attributes_per_element,
            ),
            ("xml_namespace_decls", self.max_xml_namespace_decls),
            ("subscriber_queue_bytes", self.max_subscriber_queue_bytes),
            (
                "subscriptions_per_session",
                self.max_subscriptions_per_session,
            ),
            ("sessions", self.max_sessions),
            (
                "subtree_filter_content_match_nodes",
                self.max_subtree_filter_content_match_nodes,
            ),
            (
                "subtree_filter_attribute_match_nodes",
                self.max_subtree_filter_attribute_match_nodes,
            ),
            ("xpath_filter_bytes", self.max_xpath_filter_bytes),
            ("xpath_filter_unions", self.max_xpath_filter_unions),
            ("xpath_filter_segments", self.max_xpath_filter_segments),
            (
                "min_sample_interval_ms",
                usize::try_from(self.min_sample_interval.as_millis()).unwrap_or(usize::MAX),
            ),
        ];
        for (name, value) in fields {
            if value == 0 {
                return Err(LimitsError::Zero { limit: name });
            }
        }

        if self.max_value_bytes > self.max_request_bytes {
            return Err(LimitsError::Inconsistent {
                detail: "max_value_bytes exceeds max_request_bytes",
            });
        }
        if self.max_xpath_filter_bytes > self.max_request_bytes {
            return Err(LimitsError::Inconsistent {
                detail: "max_xpath_filter_bytes exceeds max_request_bytes",
            });
        }

        Ok(())
    }

    /// Rejects an inbound message larger than [`Self::max_request_bytes`].
    pub fn check_request_bytes(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("request_bytes", self.max_request_bytes, actual)
    }

    /// Rejects an inbound message composed from more than
    /// [`Self::max_frame_chunks_per_message`] chunks/frames.
    pub fn check_frame_chunks(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check(
            "frame_chunks_per_message",
            self.max_frame_chunks_per_message,
            actual,
        )
    }

    /// Rejects a request addressing more than [`Self::max_paths_per_request`].
    pub fn check_paths(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("paths_per_request", self.max_paths_per_request, actual)
    }

    /// Rejects a single encoded value larger than [`Self::max_value_bytes`].
    pub fn check_value_bytes(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("value_bytes", self.max_value_bytes, actual)
    }

    /// Rejects parse depth beyond [`Self::max_xml_depth`].
    pub fn check_depth(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("xml_depth", self.max_xml_depth, actual)
    }

    /// Rejects a subscriber/notification queue larger than
    /// [`Self::max_subscriber_queue_bytes`].
    pub fn check_subscriber_queue_bytes(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check(
            "subscriber_queue_bytes",
            self.max_subscriber_queue_bytes,
            actual,
        )
    }

    /// Rejects a session that would hold more than
    /// [`Self::max_subscriptions_per_session`] subscriptions.
    pub fn check_subscriptions(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check(
            "subscriptions_per_session",
            self.max_subscriptions_per_session,
            actual,
        )
    }

    /// Rejects accepting more than [`Self::max_sessions`] concurrent sessions.
    pub fn check_sessions(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("sessions", self.max_sessions, actual)
    }

    /// Rejects a subtree filter containing more than
    /// [`Self::max_subtree_filter_content_match_nodes`] content-match nodes.
    pub fn check_subtree_filter_content_match_nodes(
        &self,
        actual: usize,
    ) -> Result<(), LimitsError> {
        Self::check(
            "subtree_filter_content_match_nodes",
            self.max_subtree_filter_content_match_nodes,
            actual,
        )
    }

    /// Rejects a subtree filter containing more than
    /// [`Self::max_subtree_filter_attribute_match_nodes`] attribute-match nodes.
    pub fn check_subtree_filter_attribute_match_nodes(
        &self,
        actual: usize,
    ) -> Result<(), LimitsError> {
        Self::check(
            "subtree_filter_attribute_match_nodes",
            self.max_subtree_filter_attribute_match_nodes,
            actual,
        )
    }

    /// Rejects an XPath filter expression larger than [`Self::max_xpath_filter_bytes`].
    pub fn check_xpath_filter_bytes(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("xpath_filter_bytes", self.max_xpath_filter_bytes, actual)
    }

    /// Rejects an XPath filter expression with more than
    /// [`Self::max_xpath_filter_unions`] union arms.
    pub fn check_xpath_filter_unions(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check("xpath_filter_unions", self.max_xpath_filter_unions, actual)
    }

    /// Rejects an XPath filter expression with more than
    /// [`Self::max_xpath_filter_segments`] location-path segments.
    pub fn check_xpath_filter_segments(&self, actual: usize) -> Result<(), LimitsError> {
        Self::check(
            "xpath_filter_segments",
            self.max_xpath_filter_segments,
            actual,
        )
    }

    #[inline]
    fn check(limit: &'static str, max: usize, actual: usize) -> Result<(), LimitsError> {
        if actual > max {
            Err(LimitsError::Exceeded { limit, max, actual })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_limits_are_valid_and_nonzero() {
        let limits = MgmtLimits::default();
        limits.validate().expect("defaults valid");
        assert!(limits.max_request_bytes > 0);
        assert!(limits.max_frame_chunks_per_message > 0);
        assert!(limits.max_value_bytes <= limits.max_request_bytes);
    }

    #[test]
    fn min_sample_interval_default_is_100ms() {
        assert_eq!(
            MgmtLimits::default().min_sample_interval,
            Duration::from_millis(100)
        );
    }

    #[test]
    fn zero_any_field_fails_closed() {
        let base = MgmtLimits::default();
        let zeroed = [
            MgmtLimits {
                max_request_bytes: 0,
                ..base
            },
            MgmtLimits {
                max_frame_chunks_per_message: 0,
                ..base
            },
            MgmtLimits {
                max_paths_per_request: 0,
                ..base
            },
            MgmtLimits {
                max_value_bytes: 0,
                ..base
            },
            MgmtLimits {
                max_xml_depth: 0,
                ..base
            },
            MgmtLimits {
                max_xml_attributes_per_element: 0,
                ..base
            },
            MgmtLimits {
                max_xml_namespace_decls: 0,
                ..base
            },
            MgmtLimits {
                max_subscriber_queue_bytes: 0,
                ..base
            },
            MgmtLimits {
                max_subscriptions_per_session: 0,
                ..base
            },
            MgmtLimits {
                max_sessions: 0,
                ..base
            },
            MgmtLimits {
                max_subtree_filter_content_match_nodes: 0,
                ..base
            },
            MgmtLimits {
                max_subtree_filter_attribute_match_nodes: 0,
                ..base
            },
            MgmtLimits {
                max_xpath_filter_bytes: 0,
                ..base
            },
            MgmtLimits {
                max_xpath_filter_unions: 0,
                ..base
            },
            MgmtLimits {
                max_xpath_filter_segments: 0,
                ..base
            },
            MgmtLimits {
                min_sample_interval: Duration::ZERO,
                ..base
            },
        ];
        for limits in zeroed {
            assert!(
                matches!(limits.validate(), Err(LimitsError::Zero { .. })),
                "a zero limit must fail validation"
            );
        }
    }

    #[test]
    fn value_larger_than_message_is_inconsistent() {
        let limits = MgmtLimits {
            max_value_bytes: 8 * 1024 * 1024,
            max_request_bytes: 1024 * 1024,
            ..MgmtLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::Inconsistent { .. })
        ));
    }

    #[test]
    fn checks_accept_at_limit_and_reject_above() {
        let limits = MgmtLimits {
            max_request_bytes: 100,
            max_frame_chunks_per_message: 2,
            max_paths_per_request: 4,
            max_value_bytes: 50,
            max_xml_depth: 8,
            max_xml_attributes_per_element: 8,
            max_xml_namespace_decls: 8,
            max_subscriber_queue_bytes: 200,
            max_subscriptions_per_session: 2,
            max_sessions: 3,
            max_subtree_filter_content_match_nodes: 1,
            max_subtree_filter_attribute_match_nodes: 1,
            max_xpath_filter_bytes: 10,
            max_xpath_filter_unions: 2,
            max_xpath_filter_segments: 3,
            min_sample_interval: Duration::from_millis(100),
        };

        // At the limit is allowed; one past is rejected with the named limit.
        assert!(limits.check_request_bytes(100).is_ok());
        assert_eq!(
            limits.check_request_bytes(101),
            Err(LimitsError::Exceeded {
                limit: "request_bytes",
                max: 100,
                actual: 101,
            })
        );
        assert!(limits.check_frame_chunks(2).is_ok());
        assert!(limits.check_frame_chunks(3).is_err());
        assert!(limits.check_paths(4).is_ok());
        assert!(limits.check_paths(5).is_err());
        assert!(limits.check_value_bytes(50).is_ok());
        assert!(limits.check_value_bytes(51).is_err());
        assert!(limits.check_depth(8).is_ok());
        assert!(limits.check_depth(9).is_err());
        assert!(limits.check_subscriber_queue_bytes(200).is_ok());
        assert!(limits.check_subscriber_queue_bytes(201).is_err());
        assert!(limits.check_subscriptions(2).is_ok());
        assert!(limits.check_subscriptions(3).is_err());
        assert!(limits.check_sessions(3).is_ok());
        assert!(limits.check_sessions(4).is_err());
        assert!(limits.check_subtree_filter_content_match_nodes(1).is_ok());
        assert!(limits.check_subtree_filter_content_match_nodes(2).is_err());
        assert!(limits.check_subtree_filter_attribute_match_nodes(1).is_ok());
        assert!(limits
            .check_subtree_filter_attribute_match_nodes(2)
            .is_err());
        assert!(limits.check_xpath_filter_bytes(10).is_ok());
        assert!(limits.check_xpath_filter_bytes(11).is_err());
        assert!(limits.check_xpath_filter_unions(2).is_ok());
        assert!(limits.check_xpath_filter_unions(3).is_err());
        assert!(limits.check_xpath_filter_segments(3).is_ok());
        assert!(limits.check_xpath_filter_segments(4).is_err());
    }

    #[test]
    fn error_display_is_payload_free() {
        let err = LimitsError::Exceeded {
            limit: "request_bytes",
            max: 10,
            actual: 11,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("request_bytes"));
        assert!(rendered.contains("11"));
        assert!(rendered.contains("10"));
    }
}
