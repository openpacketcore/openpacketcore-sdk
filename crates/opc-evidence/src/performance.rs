use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Performance baseline struct.
///
/// Complies with performance-baseline.schema.json, only serializing required fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceBaseline {
    pub schema_version: String,
    pub generated_at: String,
    pub benchmark: String,
    pub metrics: Vec<PerformanceMetric>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression_status: Option<RegressionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceMetric {
    pub name: String,
    pub unit: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentMetadata {
    pub os: String,
    pub arch: String,
    pub rust_version: Option<String>,
    pub cpu_summary: Option<String>,
    pub test_profile: String,
    pub command: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegressionStatus {
    Pass,
    Fail,
    Regression,
}

/// Evaluates if a metric value has regressed compared to a threshold.
pub fn evaluate_threshold(
    current_value: f64,
    threshold: f64,
    lower_is_better: bool,
) -> RegressionStatus {
    if lower_is_better {
        if current_value <= threshold {
            RegressionStatus::Pass
        } else {
            RegressionStatus::Regression
        }
    } else {
        if current_value >= threshold {
            RegressionStatus::Pass
        } else {
            RegressionStatus::Regression
        }
    }
}

/// Redacts secrets, usernames, IPs, and home paths from a string.
pub fn redact_secrets_and_paths(input: &str) -> String {
    let mut redacted = input.to_string();

    // 1. Redact home directory
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() && home != "/" {
            redacted = redacted.replace(&home, "<home>");
        }
    }

    // 2. Redact usernames from USER or USERNAME env vars
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            redacted = redacted.replace(&user, "<user>");
        }
    }
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.is_empty() {
            redacted = redacted.replace(&user, "<user>");
        }
    }

    // 3. Redact IPv4 addresses
    redacted = redact_ips(&redacted);

    redacted
}

fn redact_ips(input: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut j = i;
            let mut dot_count = 0;
            let mut segments = 0;
            let mut current_segment_len = 0;
            let mut is_ip = true;

            while j < chars.len() {
                let c = chars[j];
                if c.is_ascii_digit() {
                    current_segment_len += 1;
                    if current_segment_len > 3 {
                        is_ip = false;
                        break;
                    }
                } else if c == '.' {
                    dot_count += 1;
                    segments += 1;
                    current_segment_len = 0;
                    if dot_count > 3 || segments > 3 {
                        is_ip = false;
                        break;
                    }
                } else {
                    break;
                }
                j += 1;
            }

            if is_ip && dot_count == 3 && current_segment_len > 0 && current_segment_len <= 3 {
                result.push_str("<ip-redacted>");
                i = j;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Captures environment details safely.
pub fn capture_environment(test_profile: String, command: String) -> EnvironmentMetadata {
    let rust_version = get_rust_version();
    let cpu_summary = get_cpu_summary();

    EnvironmentMetadata {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        rust_version,
        cpu_summary,
        test_profile,
        command: redact_secrets_and_paths(&command),
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    }
}

fn get_rust_version() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn get_cpu_summary() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("model name") {
                    if let Some(name) = line.split(':').nth(1) {
                        return Some(name.trim().to_string());
                    }
                }
            }
        }
    }

    Some(format!("{} logical CPUs", num_cpus::get()))
}
