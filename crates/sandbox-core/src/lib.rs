//! Sandbox handles, mechanism trait, persistent state, and secret injection.

mod control;
mod secrets;
mod state;

pub use control::{ControlChannel, ControlError};
pub use secrets::{resolve_secrets, SecretError, SecretMap};
pub use state::{SandboxRecord, SandboxState, StateError, Store};

use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use anyhow::Result;
use sandbox_policy::{MechanismKind, SandboxPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from mechanism operations.
#[derive(Debug, Error)]
pub enum MechanismError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("mechanism not available: {0}")]
    Unavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

/// Request to create or run a sandbox.
#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub name: String,
    pub policy: SandboxPolicy,
    pub workdir: PathBuf,
    /// If true, container/process is ephemeral (removed after run).
    pub ephemeral: bool,
    /// Command for ephemeral run; empty means keep-alive / sleep for persistent.
    pub command: Vec<String>,
    /// Extra environment (already-resolved secrets + user env).
    pub env: Vec<(String, String)>,
}

/// Result of creating a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    pub name: String,
    pub mechanism: MechanismKind,
    pub runtime_id: String,
    pub proxy_port: Option<u16>,
    pub log_path: Option<PathBuf>,
    /// Set for ephemeral runs so the CLI can propagate the child exit code.
    #[serde(default)]
    pub exit_code: Option<i32>,
}

/// Exec request against an existing sandbox.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub name: String,
    pub runtime_id: String,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    pub tty: bool,
    /// Working directory inside the sandbox.
    pub cwd: Option<String>,
}

#[derive(Debug)]
pub struct ExecResult {
    pub status: ExitStatus,
}

/// Doctor / health check item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorItem {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Pluggable sandbox backend.
pub trait Mechanism: Send + Sync {
    fn kind(&self) -> MechanismKind;

    fn name(&self) -> &'static str;

    /// Availability / health checks for `ssbx doctor`.
    fn doctor(&self) -> Vec<DoctorItem>;

    /// Create a persistent sandbox (or start ephemeral run).
    fn create(&self, req: &CreateRequest) -> Result<CreateResult, MechanismError>;

    /// Execute a command in an existing sandbox.
    fn exec(&self, req: &ExecRequest) -> Result<ExecResult, MechanismError>;

    /// Remove / stop a sandbox.
    fn remove(&self, runtime_id: &str) -> Result<(), MechanismError>;

    /// Optional: fetch recent logs.
    fn logs(&self, runtime_id: &str, tail: usize) -> Result<String, MechanismError> {
        let _ = (runtime_id, tail);
        Ok(String::new())
    }
}

/// Resolve Auto mechanism based on OS and preference order.
pub fn resolve_mechanism(kind: MechanismKind) -> MechanismKind {
    match kind {
        MechanismKind::Auto => {
            if cfg!(target_os = "macos") {
                // Prefer podman/linux guest when available; callers may override after doctor.
                MechanismKind::Podman
            } else if cfg!(target_os = "linux") {
                MechanismKind::Podman
            } else {
                MechanismKind::Mac
            }
        }
        other => other,
    }
}

/// Config / state root directory.
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("simple-sandbox")
}

/// Ensure a directory exists.
pub fn ensure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}
