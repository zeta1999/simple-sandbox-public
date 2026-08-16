//! YAML sandbox policy schema and limited-core resource preflight.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use limited_core::resource::{Device, ExtentEngine, ExtentPool, ExtentType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors loading or validating a sandbox policy.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid policy: {0}")]
    Invalid(String),
    #[error("resource preflight failed: {0}")]
    Preflight(String),
}

/// Top-level sandbox policy (mechanism-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxPolicy {
    pub version: u32,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub resources: ResourcePolicy,
    #[serde(default)]
    pub mechanism: Option<MechanismKind>,
    /// Named secrets to inject as environment variables (resolved by supervisor).
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            resources: ResourcePolicy::default(),
            mechanism: None,
            secrets: Vec::new(),
        }
    }
}

/// Filesystem allowlists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemPolicy {
    /// Bind the host working directory as `/workspace` (or equivalent).
    #[serde(default = "default_true")]
    pub workdir: bool,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            workdir: true,
            read_only: Vec::new(),
            read_write: vec!["/workspace".into(), "/tmp".into()],
        }
    }
}

/// Network policy. Default is deny-all (`none`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: NetworkMode,
    #[serde(default)]
    pub endpoints: Vec<NetworkEndpoint>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::None,
            endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No network access (default).
    #[default]
    None,
    /// Only listed endpoints via userspace proxy.
    Allowlist,
    /// Unrestricted host networking (mechanism-dependent; warn on use).
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEndpoint {
    pub host: String,
    #[serde(default = "default_https_port")]
    pub port: u16,
}

fn default_https_port() -> u16 {
    443
}

impl NetworkEndpoint {
    pub fn key(&self) -> String {
        format!("{}:{}", self.host.to_ascii_lowercase(), self.port)
    }
}

/// CPU / memory resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourcePolicy {
    /// Fractional CPUs (e.g. 2.0).
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    /// Human size like `2G`, `512M`, or raw bytes as integer string.
    #[serde(default = "default_memory")]
    pub memory: String,
}

fn default_cpus() -> f64 {
    2.0
}

fn default_memory() -> String {
    "2G".into()
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpus: default_cpus(),
            memory: default_memory(),
        }
    }
}

impl ResourcePolicy {
    /// Parse memory string into bytes.
    pub fn memory_bytes(&self) -> Result<u64, PolicyError> {
        parse_size(&self.memory)
    }

    /// Millicores (cpus * 1000) for accounting.
    pub fn millicores(&self) -> u64 {
        (self.cpus * 1000.0).round() as u64
    }
}

/// Which backend to use.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MechanismKind {
    Podman,
    Mac,
    Krun,
    /// Pick based on host OS / availability.
    #[default]
    Auto,
}

impl fmt::Display for MechanismKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Podman => write!(f, "podman"),
            Self::Mac => write!(f, "mac"),
            Self::Krun => write!(f, "krun"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

impl FromStr for MechanismKind {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "podman" | "linux" | "linux_podman" => Ok(Self::Podman),
            "mac" | "macos" | "seatbelt" | "mac_seatbelt" => Ok(Self::Mac),
            "krun" | "libkrun" | "linux_libkrun" => Ok(Self::Krun),
            "auto" => Ok(Self::Auto),
            other => Err(PolicyError::Invalid(format!(
                "unknown mechanism '{other}' (expected podman|mac|krun|auto)"
            ))),
        }
    }
}

/// Reference to a secret injected as an environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    /// Environment variable name inside the sandbox.
    pub env: String,
    /// Source: `env:NAME` (host env) or `file:PATH` or `value:` (literal, discouraged).
    pub from: String,
}

impl SandboxPolicy {
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let text = fs::read_to_string(path)?;
        Self::parse_yaml(&text)
    }

    pub fn parse_yaml(text: &str) -> Result<Self, PolicyError> {
        let policy: SandboxPolicy = serde_yaml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_yaml(&self) -> Result<String, PolicyError> {
        Ok(serde_yaml::to_string(self)?)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}",
                self.version
            )));
        }
        if self.resources.cpus <= 0.0 {
            return Err(PolicyError::Invalid("resources.cpus must be > 0".into()));
        }
        let _ = self.resources.memory_bytes()?;
        match self.network.mode {
            NetworkMode::Allowlist if self.network.endpoints.is_empty() => {
                return Err(PolicyError::Invalid(
                    "network.mode=allowlist requires at least one endpoint".into(),
                ));
            }
            NetworkMode::None | NetworkMode::Unrestricted | NetworkMode::Allowlist => {}
        }
        for secret in &self.secrets {
            if secret.env.is_empty() || secret.from.is_empty() {
                return Err(PolicyError::Invalid(
                    "secrets entries need non-empty env and from".into(),
                ));
            }
        }
        Ok(())
    }

    /// Content hash for change detection.
    pub fn content_hash(&self) -> Result<String, PolicyError> {
        let yaml = self.to_yaml()?;
        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// Effective mechanism (Auto left as Auto for callers to resolve).
    pub fn mechanism_or_auto(&self) -> MechanismKind {
        self.mechanism.unwrap_or(MechanismKind::Auto)
    }

    /// Restrictive default: workdir RW, no network, 2 CPU / 2G.
    pub fn restrictive_default() -> Self {
        Self::default()
    }
}

/// Host capacity used for limited-core preflight accounting.
#[derive(Debug, Clone)]
pub struct HostCapacity {
    pub memory_bytes: u64,
    pub millicores: u64,
}

impl Default for HostCapacity {
    fn default() -> Self {
        // Conservative defaults when we cannot probe the host.
        Self {
            memory_bytes: 8 * 1024 * 1024 * 1024,
            millicores: 8000,
        }
    }
}

/// Run limited-core extent preflight: reject policies that oversubscribe host pools.
pub fn preflight(policy: &SandboxPolicy, host: &HostCapacity) -> Result<(), PolicyError> {
    policy.validate()?;

    let mut engine = ExtentEngine::new();
    let mut device = Device::new("host");
    device.add_extent(ExtentPool::new("RAM", host.memory_bytes, ExtentType::Bytes));
    device.add_extent(ExtentPool::new("CPU", host.millicores, ExtentType::Count));
    engine.add_device(device);

    let need_mem = policy.resources.memory_bytes()?;
    let need_cpu = policy.resources.millicores();

    engine
        .allocate("host", "RAM", need_mem)
        .map_err(PolicyError::Preflight)?;
    engine
        .allocate("host", "CPU", need_cpu)
        .map_err(PolicyError::Preflight)?;

    Ok(())
}

/// Parse sizes like `2G`, `512M`, `1024K`, `100` (bytes).
pub fn parse_size(s: &str) -> Result<u64, PolicyError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PolicyError::Invalid("empty memory size".into()));
    }
    let (num, mult) = match s.as_bytes().last().copied() {
        Some(b @ (b'K' | b'k' | b'M' | b'm' | b'G' | b'g' | b'T' | b't')) => {
            let n = &s[..s.len() - 1];
            let m = match b {
                b'K' | b'k' => 1024u64,
                b'M' | b'm' => 1024 * 1024,
                b'G' | b'g' => 1024 * 1024 * 1024,
                b'T' | b't' => 1024 * 1024 * 1024 * 1024,
                _ => unreachable!(),
            };
            (n, m)
        }
        _ => (s, 1u64),
    };
    let value: u64 = num
        .parse()
        .map_err(|_| PolicyError::Invalid(format!("invalid memory size '{s}'")))?;
    value
        .checked_mul(mult)
        .ok_or_else(|| PolicyError::Invalid(format!("memory size overflow '{s}'")))
}

/// Resolve relative FS paths against a workdir for absolute host paths.
pub fn resolve_host_paths(
    policy: &FilesystemPolicy,
    workdir: &Path,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let resolve = |p: &str| -> PathBuf {
        let path = PathBuf::from(p);
        if path.is_absolute() {
            path
        } else {
            workdir.join(path)
        }
    };
    let ro: Vec<_> = policy.read_only.iter().map(|p| resolve(p)).collect();
    let mut rw: Vec<_> = policy.read_write.iter().map(|p| resolve(p)).collect();
    if policy.workdir {
        let ws = workdir.to_path_buf();
        if !rw.iter().any(|p| p == &ws) {
            rw.push(ws);
        }
    }
    (ro, rw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaultish_policy() {
        let yaml = r#"
version: 1
filesystem:
  workdir: true
  read_write: ["/workspace", "/tmp"]
network:
  mode: none
resources:
  cpus: 1
  memory: 512M
"#;
        let p = SandboxPolicy::parse_yaml(yaml).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.resources.memory_bytes().unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn allowlist_requires_endpoints() {
        let yaml = r#"
version: 1
network:
  mode: allowlist
  endpoints: []
"#;
        assert!(SandboxPolicy::parse_yaml(yaml).is_err());
    }

    #[test]
    fn preflight_rejects_oversize_memory() {
        let mut p = SandboxPolicy::default();
        p.resources.memory = "64G".into();
        let host = HostCapacity {
            memory_bytes: 8 * 1024 * 1024 * 1024,
            millicores: 8000,
        };
        let err = preflight(&p, &host).unwrap_err();
        assert!(matches!(err, PolicyError::Preflight(_)));
    }

    #[test]
    fn preflight_accepts_reasonable() {
        let p = SandboxPolicy::default();
        let host = HostCapacity::default();
        preflight(&p, &host).unwrap();
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("100").unwrap(), 100);
    }

    #[test]
    fn content_hash_stable() {
        let p = SandboxPolicy::default();
        assert_eq!(p.content_hash().unwrap(), p.content_hash().unwrap());
    }
}
