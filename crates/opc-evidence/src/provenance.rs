use crate::EvidenceError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ProvenanceSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ProvenancePredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceSubject {
    pub name: String,
    pub digest: ProvenanceDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceDigest {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenancePredicate {
    pub builder: BuilderIdentity,
    pub build_type: String,
    pub invocation: InvocationDetails,
    pub metadata: BuildMetadata,
    pub materials: Vec<ProvenanceMaterial>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuilderIdentity {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationDetails {
    pub command: Vec<String>,
    pub environment: InvocationEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationEnvironment {
    pub git_commit: String,
    pub worktree_dirty: bool,
    pub sdk_version: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildMetadata {
    pub build_started_on: String,
    pub reproducible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceMaterial {
    pub uri: String,
    pub digest: ProvenanceDigest,
}

/// Generates a SLSA/in-toto-style provenance statement deterministically.
#[allow(clippy::too_many_arguments)]
pub fn generate_provenance(
    subjects: Vec<ProvenanceSubject>,
    git_commit: String,
    worktree_dirty: bool,
    builder_id: String,
    build_command: Vec<String>,
    materials: Vec<ProvenanceMaterial>,
    sdk_version: String,
    tool_version: String,
    timestamp: String,
) -> Result<ProvenanceStatement, EvidenceError> {
    if git_commit.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "git commit cannot be empty".into(),
        ));
    }
    if builder_id.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "builder ID cannot be empty".into(),
        ));
    }

    Ok(ProvenanceStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".to_string(),
        subject: subjects,
        predicate_type: "https://slsa.dev/provenance/v0.2".to_string(),
        predicate: ProvenancePredicate {
            builder: BuilderIdentity { id: builder_id },
            build_type: "https://openpacketcore.dev/build/v1".to_string(),
            invocation: InvocationDetails {
                command: build_command,
                environment: InvocationEnvironment {
                    git_commit,
                    worktree_dirty,
                    sdk_version,
                    tool_version,
                },
            },
            metadata: BuildMetadata {
                build_started_on: timestamp,
                reproducible: true,
            },
            materials,
        },
    })
}
