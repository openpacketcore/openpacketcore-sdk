//! Redaction-safe error types for GTP-U dataplane backend operations.
//!
//! Error variants deliberately carry only stable operation/field labels and
//! static payload-free reasons. They never hold TEIDs, subscriber addresses, or
//! peer addresses, so `Debug` and `Display` are safe for logs and support
//! bundles.

use std::io;

use thiserror::Error;

/// Why a `BPF_PROG_LOAD` was refused before the kernel's verifier reached a
/// verdict on the program.
///
/// `bpf(2)` reports these through errno, and the mapping is not total. An LSM
/// denial of `bpf { prog_load }` surfaces as `EACCES` — the same errno a
/// verifier rejection uses — so errno alone cannot separate them. The
/// classification here treats an `EACCES` as a policy denial only when the
/// kernel returned no verifier output, which is the signal that the verifier
/// never ran. Rust maps both `EPERM` and `EACCES` to
/// [`io::ErrorKind::PermissionDenied`], so an error carrying no errno at all
/// is [`ProgramLoadRefusal::Indeterminate`] rather than a guess.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramLoadRefusal {
    /// `EPERM`: `CAP_BPF`/`CAP_PERFMON` was not effective, or BPF memory is
    /// still accounted against `RLIMIT_MEMLOCK` on this kernel.
    ///
    /// Operator-fixable on this node: grant the capability or raise the limit
    /// and retry here.
    Unprivileged,
    /// `EACCES` with no verifier output: an LSM (SELinux, AppArmor) denied
    /// `bpf { prog_load }` before the verifier ran.
    ///
    /// Operator-fixable on this node, in policy rather than in capabilities.
    PolicyDenied,
    /// The errno was absent, or outside the set `bpf(2)` documents for this
    /// boundary.
    ///
    /// No verdict was established. Do not read this as a verifier rejection:
    /// the point of the distinction is that condemning a node requires
    /// positive evidence, and this value is the absence of it.
    Indeterminate,
}

impl ProgramLoadRefusal {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unprivileged => "unprivileged",
            Self::PolicyDenied => "policy_denied",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl std::fmt::Display for ProgramLoadRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for safe GTP-U dataplane backend operations.
///
/// The type is `Clone` so mock/test backends can reuse injected failures. I/O
/// errors are captured only as their [`io::ErrorKind`], raw OS error code, and
/// a stable operation label; the original OS error string is intentionally
/// discarded so `Debug` and `Display` never leak addresses, TEIDs, or
/// subscriber context.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum GtpuError {
    /// The platform does not support Linux GTP-U operations.
    #[error("GTP-U dataplane operations are not supported on this platform")]
    UnsupportedPlatform,
    /// A requested feature is outside this backend's capability profile.
    #[error("GTP-U dataplane feature is unsupported: {feature}")]
    UnsupportedFeature {
        /// Stable feature label.
        feature: &'static str,
    },
    /// Kernel or socket I/O failed.
    #[error("GTP-U {operation} failed{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
        /// Raw OS error code (errno), when the source carried one.
        raw_os_error: Option<i32>,
    },
    /// The kernel reached a verdict and rejected an eBPF program at the
    /// `BPF_PROG_LOAD` boundary.
    ///
    /// This means the running kernel cannot execute this object: the remedy is
    /// to move the workload or ship a different object, not to reconfigure the
    /// node. A load that never reached a verdict is
    /// [`GtpuError::ProgramLoadRefused`] instead — see that variant for why
    /// the two must not be conflated.
    ///
    /// Verifier output is deliberately not retained because it can contain
    /// implementation details. This variant keeps the failure distinct from
    /// capability and bpffs errors while exposing only redaction-safe I/O
    /// classification.
    #[error("GTP-U {operation} was rejected by the kernel eBPF loader{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    ProgramLoadRejected {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind from `BPF_PROG_LOAD`.
        kind: io::ErrorKind,
        /// Raw OS error code (errno), when the syscall carried one.
        raw_os_error: Option<i32>,
    },
    /// The kernel refused a `BPF_PROG_LOAD` before its verifier reached a
    /// verdict on the program.
    ///
    /// Distinct from [`GtpuError::ProgramLoadRejected`] because the two call
    /// for opposite operator actions. A verifier rejection means this kernel
    /// cannot run this object. A refusal means the environment is
    /// misconfigured and the same node will accept the program once it is
    /// fixed. Reporting a refusal as a rejection turns a fixable
    /// misconfiguration into the permanent exclusion of healthy capacity.
    ///
    /// aya wraps every `bpf(2)` failure at this boundary into one error type
    /// without inspecting errno, so this classification is made here rather
    /// than left to each caller. See [`ProgramLoadRefusal`] for what errno can
    /// and cannot establish.
    #[error("GTP-U {operation} was refused by the kernel eBPF loader before verification ({class}){}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    ProgramLoadRefused {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind from `BPF_PROG_LOAD`.
        kind: io::ErrorKind,
        /// Raw OS error code (errno), when the syscall carried one.
        raw_os_error: Option<i32>,
        /// What the errno established about the refusal.
        class: ProgramLoadRefusal,
    },
    /// The requested device or PDP context already exists.
    #[error("GTP-U state already exists")]
    AlreadyExists,
    /// The requested device or PDP context was not found.
    #[error("GTP-U state not found")]
    NotFound,
    /// A safe recovery step completed, but the requested mutation was not
    /// applied and must be retried as a new operation.
    #[error("GTP-U {operation} must be retried")]
    RetryRequired {
        /// Stable operation label identifying the retriable boundary.
        operation: &'static str,
    },
    /// Configuration failed validation.
    #[error("invalid GTP-U config field '{field}': {reason}")]
    InvalidConfig {
        /// Stable field label.
        field: &'static str,
        /// Static payload-free reason.
        reason: &'static str,
    },
    /// A mutation or cleanup may be partial, ACK-uncertain, or otherwise have
    /// an unproven final state.
    #[error("GTP-U {operation} outcome is indeterminate")]
    StateIndeterminate {
        /// Stable operation label.
        operation: &'static str,
    },
}

impl GtpuError {
    /// Build an `InvalidConfig` error with a static reason.
    pub fn invalid_config(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidConfig { field, reason }
    }

    /// Build an `Io` error with a stable operation label.
    ///
    /// The original OS error message is discarded; only [`io::ErrorKind`] and
    /// raw OS error code are retained to keep diagnostics redaction-safe.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }

    /// Build a redaction-safe eBPF program-load rejection.
    ///
    /// The original I/O message and kernel verifier log are not retained.
    pub(crate) fn program_load_rejected(operation: &'static str, source: &io::Error) -> Self {
        Self::ProgramLoadRejected {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }

    /// Classify a `BPF_PROG_LOAD` failure into a verdict or a refusal.
    ///
    /// `verifier_produced_output` must be true only when the kernel returned a
    /// non-empty verifier log, which proves the verifier ran. It is the only
    /// evidence that separates a verifier rejection from an LSM denial, since
    /// `bpf(2)` reports both as `EACCES`. The log itself is inspected by the
    /// caller and never retained here.
    ///
    /// `E2BIG` and `EINVAL` are verdicts: the kernel evaluated the object and
    /// will not run it, so reconfiguring the node does not help. An errno
    /// outside the documented set yields a refusal classified as
    /// [`ProgramLoadRefusal::Indeterminate`], because condemning a node needs
    /// positive evidence and an unrecognized errno is not any.
    pub(crate) fn program_load_outcome(
        operation: &'static str,
        source: &io::Error,
        verifier_produced_output: bool,
    ) -> Self {
        // Architecture-independent on Linux, and this boundary is Linux-only.
        const EPERM: i32 = 1;
        const E2BIG: i32 = 7;
        const EACCES: i32 = 13;
        const EINVAL: i32 = 22;

        if verifier_produced_output {
            return Self::program_load_rejected(operation, source);
        }

        let class = match source.raw_os_error() {
            Some(EPERM) => ProgramLoadRefusal::Unprivileged,
            Some(EACCES) => ProgramLoadRefusal::PolicyDenied,
            Some(E2BIG | EINVAL) => return Self::program_load_rejected(operation, source),
            _ => ProgramLoadRefusal::Indeterminate,
        };

        Self::ProgramLoadRefused {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
            class,
        }
    }

    /// Return the I/O error kind carried by an I/O or program-load failure.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { kind, .. }
            | Self::ProgramLoadRejected { kind, .. }
            | Self::ProgramLoadRefused { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Return the raw OS error code (errno) carried by an I/O or program-load
    /// failure.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io { raw_os_error, .. }
            | Self::ProgramLoadRejected { raw_os_error, .. }
            | Self::ProgramLoadRefused { raw_os_error, .. } => *raw_os_error,
            _ => None,
        }
    }

    /// Return why a `BPF_PROG_LOAD` was refused before the verifier reached a
    /// verdict, or `None` when this error is not such a refusal.
    ///
    /// `None` does **not** mean the verifier rejected the program: check
    /// [`GtpuError::is_verifier_rejection`] for that. It is `None` for every
    /// error that is not a pre-verdict load refusal, including unrelated I/O
    /// failures.
    #[must_use]
    pub fn load_refusal(&self) -> Option<ProgramLoadRefusal> {
        match self {
            Self::ProgramLoadRefused { class, .. } => Some(*class),
            _ => None,
        }
    }

    /// Whether the kernel's verifier reached a verdict and rejected the
    /// program, meaning this kernel cannot run this object.
    ///
    /// False for a load refused before the verifier ran, so a caller may use
    /// this to decide whether to exclude a node without reimplementing the
    /// errno rules.
    #[must_use]
    pub fn is_verifier_rejection(&self) -> bool {
        matches!(self, Self::ProgramLoadRejected { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_config_display_uses_labels_only() {
        let err = GtpuError::invalid_config("device.name", "must be nonempty");
        let display = err.to_string();
        assert!(display.contains("device.name"));
        assert!(display.contains("must be nonempty"));
    }

    #[test]
    fn io_error_display_uses_operation_label_and_errno_only() {
        let source = io::Error::from_raw_os_error(95);
        let err = GtpuError::io("netlink_ack", source);
        let display = err.to_string();
        assert!(display.contains("netlink_ack"));
        assert!(display.contains("os error 95"));
    }

    #[test]
    fn io_error_debug_does_not_leak_source_message() {
        let sensitive = "subscriber=123456789012345 teid=0x12345678 addr=10.23.0.2";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, sensitive);
        let err = GtpuError::io("netlink_send", source);
        let debug = format!("{err:?}");
        assert!(debug.contains("PermissionDenied"));
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("123456789012345"));
        assert!(!debug.contains("0x12345678"));
        assert!(!debug.contains("10.23.0.2"));
    }

    #[test]
    fn program_load_rejection_is_typed_and_redaction_safe() {
        let sensitive = "subscriber=123456789012345 path=/private/bpffs/node";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, sensitive);
        let err = GtpuError::program_load_rejected("ebpf_program_load", &source);

        assert!(matches!(
            err,
            GtpuError::ProgramLoadRejected {
                operation: "ebpf_program_load",
                kind: io::ErrorKind::PermissionDenied,
                raw_os_error: None,
            }
        ));
        let rendered = format!("{err:?} {err}");
        assert!(!rendered.contains("subscriber"));
        assert!(!rendered.contains("123456789012345"));
        assert!(!rendered.contains("/private/bpffs/node"));
    }

    #[test]
    fn program_load_rejection_preserves_errno_without_source_text() {
        let source = io::Error::from_raw_os_error(13);
        let err = GtpuError::program_load_rejected("ebpf_program_load", &source);

        assert_eq!(err.io_kind(), Some(io::ErrorKind::PermissionDenied));
        assert_eq!(err.raw_os_error(), Some(13));
        assert_eq!(
            err.to_string(),
            "GTP-U ebpf_program_load was rejected by the kernel eBPF loader (os error 13)"
        );
    }

    #[test]
    fn non_io_variants_have_no_raw_os_error() {
        assert_eq!(GtpuError::NotFound.raw_os_error(), None);
        assert_eq!(GtpuError::AlreadyExists.raw_os_error(), None);
        assert_eq!(
            GtpuError::RetryRequired {
                operation: "install_pdp_context"
            }
            .raw_os_error(),
            None
        );
        assert_eq!(GtpuError::UnsupportedPlatform.raw_os_error(), None);
    }

    #[test]
    fn retry_required_uses_only_the_stable_operation_label() {
        let error = GtpuError::RetryRequired {
            operation: "install_pdp_context",
        };
        assert_eq!(
            error.to_string(),
            "GTP-U install_pdp_context must be retried"
        );
    }

    /// The defect in #547: a load refused for want of `CAP_BPF` is `EPERM`,
    /// the verifier never ran, and reporting it as a verifier rejection
    /// condemns a node that would accept the program once the capability is
    /// granted.
    #[test]
    fn eperm_without_verifier_output_is_a_refusal_not_a_rejection() {
        let error = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::from_raw_os_error(1),
            false,
        );

        assert!(!error.is_verifier_rejection());
        assert_eq!(error.load_refusal(), Some(ProgramLoadRefusal::Unprivileged));
        assert_eq!(error.raw_os_error(), Some(1));
        assert_eq!(error.io_kind(), Some(io::ErrorKind::PermissionDenied));
    }

    /// `EACCES` is the same errno for a verifier rejection and an LSM denial.
    /// Verifier output is the only thing that separates them, so it decides
    /// the classification.
    #[test]
    fn eacces_is_split_by_whether_the_verifier_produced_output() {
        let denied = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::from_raw_os_error(13),
            false,
        );
        assert!(!denied.is_verifier_rejection());
        assert_eq!(
            denied.load_refusal(),
            Some(ProgramLoadRefusal::PolicyDenied)
        );

        let rejected = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::from_raw_os_error(13),
            true,
        );
        assert!(rejected.is_verifier_rejection());
        assert_eq!(rejected.load_refusal(), None);
        assert_eq!(rejected.raw_os_error(), Some(13));
    }

    /// `E2BIG` and `EINVAL` are verdicts: the kernel evaluated the object and
    /// will not run it, so no amount of node reconfiguration helps.
    #[test]
    fn size_and_validity_errnos_are_verdicts() {
        for errno in [7, 22] {
            let error = GtpuError::program_load_outcome(
                "ebpf_program_load",
                &io::Error::from_raw_os_error(errno),
                false,
            );
            assert!(
                error.is_verifier_rejection(),
                "errno {errno} must be a verdict"
            );
            assert_eq!(error.load_refusal(), None);
        }
    }

    /// Rust collapses `EPERM` and `EACCES` into the same `ErrorKind`, so an
    /// error carrying no errno cannot be classified. It must not be guessed
    /// into a rejection, because that is the direction that costs capacity.
    #[test]
    fn a_missing_errno_is_indeterminate_rather_than_a_rejection() {
        let error = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::new(io::ErrorKind::PermissionDenied, "no errno here"),
            false,
        );

        assert!(!error.is_verifier_rejection());
        assert_eq!(
            error.load_refusal(),
            Some(ProgramLoadRefusal::Indeterminate)
        );
        assert_eq!(error.raw_os_error(), None);
    }

    #[test]
    fn load_refusal_is_none_for_unrelated_errors() {
        assert_eq!(GtpuError::UnsupportedPlatform.load_refusal(), None);
        assert!(!GtpuError::UnsupportedPlatform.is_verifier_rejection());
        let io_error = GtpuError::io("netlink_send", io::Error::from_raw_os_error(1));
        assert_eq!(io_error.load_refusal(), None);
        assert!(!io_error.is_verifier_rejection());
    }

    #[test]
    fn refusal_is_redaction_safe_and_names_its_class() {
        let sensitive = "subscriber=123456789012345 path=/private/bpffs/node";
        let error = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::new(io::ErrorKind::PermissionDenied, sensitive),
            false,
        );

        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("subscriber"));
        assert!(!rendered.contains("123456789012345"));
        assert!(!rendered.contains("/private/bpffs/node"));
        assert!(rendered.contains("indeterminate"));
    }

    #[test]
    fn refusal_display_distinguishes_itself_from_a_rejection() {
        let error = GtpuError::program_load_outcome(
            "ebpf_program_load",
            &io::Error::from_raw_os_error(1),
            false,
        );
        assert_eq!(
            error.to_string(),
            "GTP-U ebpf_program_load was refused by the kernel eBPF loader \
before verification (unprivileged) (os error 1)"
        );
    }

    #[test]
    fn refusal_class_labels_are_stable() {
        assert_eq!(ProgramLoadRefusal::Unprivileged.as_str(), "unprivileged");
        assert_eq!(ProgramLoadRefusal::PolicyDenied.as_str(), "policy_denied");
        assert_eq!(ProgramLoadRefusal::Indeterminate.as_str(), "indeterminate");
        assert_eq!(
            ProgramLoadRefusal::PolicyDenied.to_string(),
            "policy_denied"
        );
    }
}
