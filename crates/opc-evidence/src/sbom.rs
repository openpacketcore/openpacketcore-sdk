use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

use crate::EvidenceError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
    pub dependencies: Vec<SbomDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomMetadata {
    pub timestamp: String,
    pub component: SbomComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<SbomHash>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub licenses: Vec<SbomLicenseChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomLicenseChoice {
    pub license: SbomLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalReference {
    pub url: String,
    #[serde(rename = "type")]
    pub ref_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomDependency {
    #[serde(rename = "ref")]
    pub dependency_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: Vec<LockDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockDependency {
    name: String,
    version: Option<String>,
}

struct WorkspaceConfig {
    version: Option<String>,
    license: Option<String>,
    repository: Option<String>,
}

#[derive(Debug, Clone)]
struct MemberPackage {
    name: String,
    _version: String,
    license: Option<String>,
    repository: Option<String>,
}

fn parse_toml_key_value(line: &str) -> Option<(&str, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        let key = parts[0].trim();
        let val_raw = parts[1].trim();
        let val = val_raw.trim_matches(|c| c == '"' || c == '\'').to_string();
        return Some((key, val));
    }
    None
}

fn parse_root_cargo_toml(content: &str) -> WorkspaceConfig {
    let mut config = WorkspaceConfig {
        version: None,
        license: None,
        repository: None,
    };
    let mut in_workspace_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package {
            if let Some((key, val)) = parse_toml_key_value(trimmed) {
                match key {
                    "version" => config.version = Some(val),
                    "license" => config.license = Some(val),
                    "repository" => config.repository = Some(val),
                    _ => {}
                }
            }
        }
    }
    config
}

fn parse_workspace_members(content: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_workspace = false;
    let mut in_members = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace = trimmed == "[workspace]";
            in_members = false;
            continue;
        }

        if !in_workspace {
            continue;
        }

        if in_members {
            if trimmed.starts_with(']') {
                in_members = false;
                continue;
            }
            let member = trimmed.trim_matches(|c| c == '"' || c == ',' || c == ' ');
            if !member.is_empty() {
                members.push(member.to_string());
            }
            continue;
        }

        if trimmed.starts_with("members = [") {
            let after_open = trimmed
                .split_once('[')
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            let before_close = after_open.split(']').next().unwrap_or(after_open);
            for raw in before_close.split(',') {
                let member = raw.trim().trim_matches('"');
                if !member.is_empty() {
                    members.push(member.to_string());
                }
            }
            in_members = !trimmed.contains(']');
        }
    }

    members.sort();
    members.dedup();
    members
}

fn parse_member_cargo_toml(content: &str, workspace: &WorkspaceConfig) -> Option<MemberPackage> {
    let mut name = None;
    let mut version = None;
    let mut license = None;
    let mut repository = None;
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }

        // Handle direct syntax table keys:
        if in_package {
            if trimmed.starts_with("version.workspace =") {
                version = workspace.version.clone();
                continue;
            }
            if trimmed.starts_with("license.workspace =") {
                license = workspace.license.clone();
                continue;
            }
            if trimmed.starts_with("repository.workspace =") {
                repository = workspace.repository.clone();
                continue;
            }

            if let Some((key, val)) = parse_toml_key_value(trimmed) {
                match key {
                    "name" => name = Some(val),
                    "version" => {
                        if val.contains("workspace") {
                            version = workspace.version.clone();
                        } else {
                            version = Some(val);
                        }
                    }
                    "license" => {
                        if val.contains("workspace") {
                            license = workspace.license.clone();
                        } else {
                            license = Some(val);
                        }
                    }
                    "repository" => {
                        if val.contains("workspace") {
                            repository = workspace.repository.clone();
                        } else {
                            repository = Some(val);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let name = name?;
    let version = version.or_else(|| workspace.version.clone())?;
    let license = license.or_else(|| workspace.license.clone());
    let repository = repository.or_else(|| workspace.repository.clone());

    Some(MemberPackage {
        name,
        _version: version,
        license,
        repository,
    })
}

fn parse_cargo_lock(lock_content: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();
    let mut current_package: Option<LockPackage> = None;
    let mut in_deps = false;

    for line in lock_content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(pkg) = current_package.take() {
                packages.push(pkg);
            }
            current_package = Some(LockPackage {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
                dependencies: Vec::new(),
            });
            in_deps = false;
            continue;
        }

        let Some(pkg) = current_package.as_mut() else {
            continue;
        };

        if in_deps {
            if trimmed.starts_with(']') {
                in_deps = false;
            } else if trimmed.starts_with('"') && trimmed.ends_with("\",") {
                let dep = trimmed.trim_matches(|c| c == '"' || c == ',' || c == ' ');
                if let Some(dep) = parse_cargo_lock_dependency(dep) {
                    pkg.dependencies.push(dep);
                }
            } else if trimmed.starts_with('"') && trimmed.ends_with('"') {
                let dep = trimmed.trim_matches(|c| c == '"' || c == ' ');
                if let Some(dep) = parse_cargo_lock_dependency(dep) {
                    pkg.dependencies.push(dep);
                }
            }
        } else if trimmed.starts_with("name =") {
            pkg.name = trimmed
                .split('=')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string();
        } else if trimmed.starts_with("version =") {
            pkg.version = trimmed
                .split('=')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string();
        } else if trimmed.starts_with("source =") {
            pkg.source = Some(
                trimmed
                    .split('=')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        } else if trimmed.starts_with("checksum =") {
            pkg.checksum = Some(
                trimmed
                    .split('=')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        } else if trimmed.starts_with("dependencies = [") {
            in_deps = true;
        }
    }

    if let Some(pkg) = current_package {
        packages.push(pkg);
    }

    packages
}

fn parse_cargo_lock_dependency(raw: &str) -> Option<LockDependency> {
    let mut parts = raw.split_whitespace();
    let name = parts.next()?.to_string();
    if name.is_empty() {
        return None;
    }
    let version = parts
        .next()
        .filter(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(ToString::to_string);

    Some(LockDependency { name, version })
}

/// Generates a CycloneDX-compatible SBOM from the Cargo workspace details.
pub fn generate_sbom(workspace_dir: &Path) -> Result<Sbom, EvidenceError> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| EvidenceError::GapGateFailed(format!("failed to format timestamp: {}", e)))?;
    generate_sbom_at(workspace_dir, &timestamp)
}

/// Generates a CycloneDX-compatible SBOM using an explicit timestamp.
///
/// Supplying the timestamp makes the output deterministic for identical
/// workspace inputs and is the preferred release-evidence entry point.
pub fn generate_sbom_at(workspace_dir: &Path, timestamp: &str) -> Result<Sbom, EvidenceError> {
    if timestamp.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "SBOM timestamp cannot be empty".to_string(),
        ));
    }

    // 1. Read and parse root Cargo.toml
    let root_toml_path = workspace_dir.join("Cargo.toml");
    let root_toml_content = fs::read_to_string(&root_toml_path).map_err(|e| {
        EvidenceError::GapGateFailed(format!("failed to read root Cargo.toml: {}", e))
    })?;
    let workspace_config = parse_root_cargo_toml(&root_toml_content);
    let workspace_members = parse_workspace_members(&root_toml_content);

    // 2. Scan crates directory for workspace members
    let mut member_packages = HashMap::new();
    for member_pattern in workspace_members {
        let member_paths = expand_workspace_member(workspace_dir, &member_pattern)?;
        for path in member_paths {
            let member_toml_path = path.join("Cargo.toml");
            if member_toml_path.exists() {
                let member_toml_content = fs::read_to_string(&member_toml_path).map_err(|e| {
                    EvidenceError::GapGateFailed(format!("failed to read member Cargo.toml: {}", e))
                })?;
                if let Some(member) =
                    parse_member_cargo_toml(&member_toml_content, &workspace_config)
                {
                    member_packages.insert(member.name.clone(), member);
                }
            }
        }
    }

    // 3. Read and parse Cargo.lock
    let lock_path = workspace_dir.join("Cargo.lock");
    let lock_content = fs::read_to_string(&lock_path)
        .map_err(|e| EvidenceError::GapGateFailed(format!("failed to read Cargo.lock: {}", e)))?;
    let lock_packages = parse_cargo_lock(&lock_content);

    // 4. Build components list
    let mut components = Vec::new();
    let mut dependencies = Vec::new();
    let mut workspace_root_pkg = None;

    // We can designate the first workspace member as the metadata component,
    // or synthesize a workspace root component.
    // Let's look for a root member. We know "opc-evidence" is in crates/opc-evidence.
    // Let's find "opc-evidence" or default to the first workspace member we find.
    let root_member_name = if member_packages.contains_key("opc-evidence") {
        "opc-evidence".to_string()
    } else if let Some(name) = member_packages.keys().min() {
        (*name).clone()
    } else {
        return Err(EvidenceError::GapGateFailed(
            "no workspace members found".to_string(),
        ));
    };

    for pkg in &lock_packages {
        let is_member = member_packages.contains_key(&pkg.name);

        let mut license_choices = Vec::new();
        let mut ext_refs = None;

        if is_member {
            if let Some(member) = member_packages.get(&pkg.name) {
                if let Some(ref lic) = member.license {
                    license_choices.push(SbomLicenseChoice {
                        license: SbomLicense {
                            id: Some(lic.clone()),
                            name: None,
                        },
                    });
                }
                if let Some(ref repo) = member.repository {
                    ext_refs = Some(vec![ExternalReference {
                        url: repo.clone(),
                        ref_type: "vcs".to_string(),
                    }]);
                }
            }
        }

        let mut hashes = Vec::new();
        if let Some(ref chk) = pkg.checksum {
            hashes.push(SbomHash {
                alg: "SHA-256".to_string(),
                content: chk.clone(),
            });
        }

        let bom_ref = format!("pkg:cargo/{}@{}", pkg.name, pkg.version);
        let purl = format!("pkg:cargo/{}@{}", pkg.name, pkg.version);

        let comp = SbomComponent {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            component_type: if is_member { "application" } else { "library" }.to_string(),
            bom_ref: bom_ref.clone(),
            purl: Some(purl),
            hashes,
            licenses: license_choices,
            external_references: ext_refs,
        };

        if pkg.name == root_member_name {
            workspace_root_pkg = Some(comp.clone());
        }

        components.push(comp);

        if !pkg.dependencies.is_empty() {
            // In Cargo.lock, dependencies only specify names, but not versions.
            // Let's resolve dependency names to their respective bom-ref in lock_packages.
            let mut depends_on = Vec::new();
            for dep in &pkg.dependencies {
                // Find matching package in lock packages (usually name matches)
                // If there are multiple versions of the same dependency, pick the first one or matches.
                if let Some(dep_pkg) = lock_packages.iter().find(|p| {
                    p.name == dep.name
                        && dep
                            .version
                            .as_ref()
                            .map(|version| p.version == *version)
                            .unwrap_or(true)
                }) {
                    depends_on.push(format!("pkg:cargo/{}@{}", dep_pkg.name, dep_pkg.version));
                }
            }
            dependencies.push(SbomDependency {
                dependency_ref: bom_ref,
                depends_on,
            });
        }
    }

    components.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));
    dependencies.sort_by(|a, b| a.dependency_ref.cmp(&b.dependency_ref));

    let root_comp = workspace_root_pkg.ok_or_else(|| {
        EvidenceError::GapGateFailed(format!(
            "root workspace component '{}' not found",
            root_member_name
        ))
    })?;

    let serial_number = deterministic_serial_number(&components, &dependencies);
    Ok(Sbom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.4".to_string(),
        serial_number,
        version: 1,
        metadata: SbomMetadata {
            timestamp: timestamp.to_string(),
            component: root_comp,
        },
        components,
        dependencies,
    })
}

fn expand_workspace_member(
    workspace_dir: &Path,
    member_pattern: &str,
) -> Result<Vec<std::path::PathBuf>, EvidenceError> {
    if let Some(prefix) = member_pattern.strip_suffix("/*") {
        let dir = workspace_dir.join(prefix);
        let mut paths = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| {
            EvidenceError::GapGateFailed(format!("failed to read workspace member directory: {e}"))
        })? {
            let entry = entry.map_err(|e| {
                EvidenceError::GapGateFailed(format!(
                    "failed to read workspace member directory entry: {e}"
                ))
            })?;
            let path = entry.path();
            if path.is_dir() {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    } else {
        Ok(vec![workspace_dir.join(member_pattern)])
    }
}

fn deterministic_serial_number(
    components: &[SbomComponent],
    dependencies: &[SbomDependency],
) -> String {
    let mut seed = String::new();
    for component in components {
        seed.push_str(&component.bom_ref);
        seed.push('\n');
    }
    for dependency in dependencies {
        seed.push_str(&dependency.dependency_ref);
        seed.push_str(" -> ");
        seed.push_str(&dependency.depends_on.join(","));
        seed.push('\n');
    }
    let digest = crate::manifest::compute_digest(seed.as_bytes());
    let hex = digest.trim_start_matches("sha256:");
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
