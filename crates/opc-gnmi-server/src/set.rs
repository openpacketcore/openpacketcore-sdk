//! Protocol-neutral gNMI Set model.

use opc_config_model::{ConfigOperation, YangPath};
use opc_mgmt_limits::MgmtLimits;

use crate::{GnmiError, NormalizedValue};

/// gNMI Set operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOperation {
    /// `delete`.
    Delete,
    /// `replace`.
    Replace,
    /// `update`.
    Update,
}

impl SetOperation {
    /// Stable operation label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Replace => "replace",
            Self::Update => "update",
        }
    }
}

/// Schema-resolved, value-normalized gNMI Set request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizedSet {
    /// Delete paths.
    pub deletes: Vec<YangPath>,
    /// Replace paths and normalized JSON values.
    pub replaces: Vec<(YangPath, NormalizedValue)>,
    /// Update paths and normalized JSON values.
    pub updates: Vec<(YangPath, NormalizedValue)>,
}

impl NormalizedSet {
    /// Builds an empty normalized Set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total addressed operation count.
    pub fn len(&self) -> usize {
        self.deletes.len() + self.replaces.len() + self.updates.len()
    }

    /// Whether the set contains no operations.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates operation count and non-empty semantics.
    pub fn validate(&self, limits: &MgmtLimits) -> Result<(), GnmiError> {
        if self.is_empty() {
            return Err(GnmiError::invalid("gNMI Set request is empty"));
        }
        limits
            .check_paths(self.len())
            .map_err(GnmiError::from_limits)
    }

    /// Stable changed-path hint for config-bus request metadata.
    pub fn changed_paths_hint(&self) -> Vec<YangPath> {
        let mut paths = Vec::with_capacity(self.len());
        paths.extend(self.deletes.iter().cloned());
        paths.extend(self.replaces.iter().map(|(path, _)| path.clone()));
        paths.extend(self.updates.iter().map(|(path, _)| path.clone()));
        paths
    }

    /// Selects the coarse config-bus operation shape.
    ///
    /// The config bus derives authoritative changed paths from the candidate
    /// diff. This helper only selects the stable high-level operation code.
    pub fn config_operation(&self) -> Result<ConfigOperation, GnmiError> {
        if self.is_empty() {
            return Err(GnmiError::invalid("gNMI Set request is empty"));
        }
        if !self.deletes.is_empty() && self.replaces.is_empty() && self.updates.is_empty() {
            Ok(ConfigOperation::Delete)
        } else if self.deletes.is_empty() && !self.replaces.is_empty() && self.updates.is_empty() {
            Ok(ConfigOperation::Replace)
        } else {
            Ok(ConfigOperation::Patch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encoding, NormalizedValue};

    fn path(value: &str) -> YangPath {
        YangPath::new(value).expect("path")
    }

    fn json(value: &str) -> NormalizedValue {
        NormalizedValue::new(Encoding::JsonIetf, value, &MgmtLimits::default()).expect("json")
    }

    #[test]
    fn validates_non_empty_and_limits() {
        let limits = MgmtLimits {
            max_paths_per_request: 1,
            ..MgmtLimits::default()
        };
        let empty = NormalizedSet::new();
        assert!(empty.validate(&limits).is_err());

        let set = NormalizedSet {
            deletes: vec![path("/a:b")],
            replaces: vec![(path("/a:c"), json("1"))],
            updates: Vec::new(),
        };
        assert!(set.validate(&limits).is_err());
    }

    #[test]
    fn config_operation_is_conservative() {
        assert_eq!(
            NormalizedSet {
                deletes: vec![path("/a:b")],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Delete
        );
        assert_eq!(
            NormalizedSet {
                replaces: vec![(path("/a:b"), json("1"))],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Replace
        );
        assert_eq!(
            NormalizedSet {
                replaces: vec![(path("/a:b"), json("1"))],
                updates: vec![(path("/a:c"), json("2"))],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Patch
        );
    }
}
