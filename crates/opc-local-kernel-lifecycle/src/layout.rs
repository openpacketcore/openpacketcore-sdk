use crate::{LocalArtifact, LocalLifecycleError as Error};
use opc_linux_gtpu_sys::tc::{LocalKernelScope, ScopeError};
use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Layout {
    children: BTreeMap<String, Layout>,
    // Some(true) is an artifact leaf inspected by its backend; Some(false)
    // is a preserved control-directory inode whose contents must be empty.
    leaf: Option<bool>,
}
impl Layout {
    pub(crate) fn new(artifacts: &[Arc<dyn LocalArtifact>]) -> Result<Self, Error> {
        let mut layout = Self::default();
        let mut count = 0;
        for artifact in artifacts {
            layout.insert(artifact.artifact().directory(), true)?;
            for path in artifact.preserved_empty_directories() {
                count += 1;
                if count > 256 {
                    return Err(Error::InvalidPlan);
                }
                layout.insert(&path, false)?;
            }
        }
        Ok(layout)
    }
    fn insert(&mut self, path: &Path, artifact: bool) -> Result<(), Error> {
        let text = path.to_str().ok_or(Error::InvalidPlan)?;
        let parts = text.split('/').collect::<Vec<_>>();
        if text.len() > 1024
            || parts.len() > 8
            || parts
                .iter()
                .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains('\0'))
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(Error::InvalidPlan);
        }
        let mut node = self;
        for part in parts {
            if node.leaf.is_some() {
                return Err(Error::InvalidPlan);
            }
            node = node.children.entry(part.to_owned()).or_default();
        }
        if !node.children.is_empty() || node.leaf.is_some_and(|previous| previous || artifact) {
            return Err(Error::InvalidPlan);
        }
        node.leaf = Some(artifact);
        Ok(())
    }
    pub(crate) fn verify(&self, scope: &LocalKernelScope) -> Result<(), Error> {
        self.verify_entries(scope, Path::new(""), scope.pin_root_entries()?)?;
        scope.verify()?;
        Ok(())
    }
    fn verify_entries(
        &self,
        scope: &LocalKernelScope,
        parent: &Path,
        entries: Vec<String>,
    ) -> Result<(), Error> {
        for name in entries {
            let node = self.children.get(&name).ok_or(ScopeError::Conflict)?;
            let path = parent.join(name);
            let directory = scope.pin_directory(&path)?.ok_or(ScopeError::Conflict)?;
            match node.leaf {
                Some(true) => (), // ArtifactInventory inspects every leaf pin.
                Some(false) if !directory.entries()?.is_empty() => {
                    return Err(ScopeError::Conflict.into())
                }
                Some(false) => (),
                None => node.verify_entries(scope, &path, directory.entries()?)?,
            }
        }
        Ok(())
    }
}
