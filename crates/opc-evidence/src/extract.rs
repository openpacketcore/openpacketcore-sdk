use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{parse_tags, ConformanceTag, EvidenceError};

/// An extracted conformance tag with location and context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedTag {
    pub file_path: String,
    pub line_number: usize,
    pub tag: ConformanceTag,
    pub context: Option<String>,
}

/// A parsed tag extraction error, tracked when not in strict mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionError {
    pub file_path: String,
    pub line_number: usize,
    pub error: String,
}

/// Scans a single source file for conformance tags.
///
/// Paths in the output are made relative to `base_dir` to avoid leaking absolute private paths.
pub fn scan_file(
    path: &Path,
    base_dir: &Path,
    strict: bool,
) -> Result<(Vec<ExtractedTag>, Vec<ExtractionError>), EvidenceError> {
    let safe_path = safe_display_path(path, base_dir);
    let content = fs::read_to_string(path).map_err(|e| {
        EvidenceError::InvalidTag(format!("failed to read source file {safe_path}: {e}"))
    })?;

    let lines: Vec<&str> = content.lines().collect();
    let mut extracted = Vec::new();
    let mut errors = Vec::new();

    let file_path_str = safe_path;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;

        // Only call parse_tags if the line contains a tag pattern,
        // or in strict mode if it has a comment indicator.
        let trimmed = line.trim();
        let is_comment = trimmed.starts_with("//") || trimmed.starts_with("///");
        if !is_comment {
            continue;
        }

        match parse_tags(line, strict) {
            Ok(tags) => {
                for tag in tags {
                    // Try to find the next non-comment line as context
                    let mut context = None;
                    let limit = std::cmp::min(lines.len(), idx + 6);
                    for candidate_line in lines.iter().take(limit).skip(idx + 1) {
                        let candidate = candidate_line.trim();
                        if !candidate.is_empty()
                            && !candidate.starts_with("//")
                            && !candidate.starts_with("/*")
                        {
                            context = Some(candidate.to_string());
                            break;
                        }
                    }
                    extracted.push(ExtractedTag {
                        file_path: file_path_str.clone(),
                        line_number: line_num,
                        tag,
                        context,
                    });
                }
            }
            Err(e) => {
                if strict {
                    return Err(e);
                } else {
                    errors.push(ExtractionError {
                        file_path: file_path_str.clone(),
                        line_number: line_num,
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    Ok((extracted, errors))
}

/// Recursively scans a directory for `.rs` files and extracts conformance tags.
///
/// Output is deterministically ordered by file path (alphabetical) and line number.
pub fn scan_directory(
    dir: &Path,
    strict: bool,
) -> Result<(Vec<ExtractedTag>, Vec<ExtractionError>), EvidenceError> {
    if !dir.is_dir() {
        return Err(EvidenceError::MissingArtifact(safe_display_path(dir, dir)));
    }

    let mut files = Vec::new();
    collect_rs_files(dir, dir, &mut files)?;
    files.sort();

    let mut all_extracted = Vec::new();
    let mut all_errors = Vec::new();

    for file in files {
        let (extracted, errors) = scan_file(&file, dir, strict)?;
        all_extracted.extend(extracted);
        all_errors.extend(errors);
    }

    Ok((all_extracted, all_errors))
}

fn collect_rs_files(
    dir: &Path,
    base_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), EvidenceError> {
    for entry in fs::read_dir(dir).map_err(|e| {
        EvidenceError::InvalidTag(format!(
            "failed to read source directory {}: {e}",
            safe_display_path(dir, base_dir)
        ))
    })? {
        let entry = entry.map_err(|e| {
            EvidenceError::InvalidTag(format!(
                "failed to read source directory entry under {}: {e}",
                safe_display_path(dir, base_dir)
            ))
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, base_dir, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn safe_display_path(path: &Path, base_dir: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(base_dir) {
        let rendered = relative.to_string_lossy();
        if !rendered.is_empty() {
            return rendered.to_string();
        }
    }

    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "<source-tree>".to_string())
}
