//! macOS seatbelt (`sandbox-exec`) mechanism — no sudo, no extra users.
//!
//! Resource limits use `setrlimit` (soft caps; macOS hard memory isolation is weaker
//! than Linux cgroups). Network deny uses seatbelt; allowlist uses a userspace proxy
//! via HTTP(S)_PROXY.

use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use libc::{rlim_t, setrlimit, RLIMIT_CPU};
#[cfg(not(target_os = "macos"))]
use libc::{RLIMIT_AS, RLIMIT_DATA};
use sandbox_core::{
    CreateRequest, CreateResult, DoctorItem, ExecRequest, ExecResult, Mechanism, MechanismError,
};
use sandbox_policy::{MechanismKind, NetworkMode};
use tempfile::NamedTempFile;
use tracing::{info, warn};

/// Persistent mac sandbox: track child PIDs loosely via a state file under config.
#[derive(Debug, Default)]
pub struct MacMechanism {
    /// Directory for seatbelt profiles / pid files (optional override).
    pub state_dir: Option<PathBuf>,
}

impl MacMechanism {
    pub fn new() -> Self {
        Self::default()
    }

    fn sandbox_exec_available() -> bool {
        which_sandbox_exec().is_some()
    }
}

fn which_sandbox_exec() -> Option<PathBuf> {
    let candidates = ["/usr/bin/sandbox-exec", "/usr/local/bin/sandbox-exec"];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Generate a deny-by-default seatbelt profile from policy.
pub fn generate_seatbelt_profile(
    policy: &sandbox_policy::SandboxPolicy,
    workdir: &Path,
) -> Result<String, MechanismError> {
    let workdir = workdir
        .canonicalize()
        .unwrap_or_else(|_| workdir.to_path_buf());
    let workdir_s = workdir.display().to_string();

    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(allow process*)".to_string(),
        "(allow sysctl*)".to_string(),
        "(allow mach*)".to_string(),
        "(allow ipc*)".to_string(),
        "(allow signal)".to_string(),
        "(allow file-read-metadata)".to_string(),
    ];

    // System paths needed to run binaries
    for p in [
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/private/var/db",
        "/dev",
        "/private/tmp",
        "/tmp",
        "/etc",
        "/private/etc",
        "/Applications",
    ] {
        lines.push(format!("(allow file-read* (subpath \"{p}\"))"));
    }
    lines.push("(allow file-read* (literal \"/\"))".into());
    lines.push("(allow file-ioctl (literal \"/dev/null\"))".into());
    lines.push("(allow file-write* (literal \"/dev/null\"))".into());
    lines.push("(allow file-write* (literal \"/dev/dtracehelper\"))".into());

    // Workdir RW
    if policy.filesystem.workdir {
        lines.push(format!("(allow file-read* (subpath \"{workdir_s}\"))"));
        lines.push(format!("(allow file-write* (subpath \"{workdir_s}\"))"));
    }

    for p in &policy.filesystem.read_only {
        let path = resolve_path(p, &workdir);
        lines.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            path.display()
        ));
    }
    for p in &policy.filesystem.read_write {
        let path = resolve_path(p, &workdir);
        lines.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            path.display()
        ));
        lines.push(format!(
            "(allow file-write* (subpath \"{}\"))",
            path.display()
        ));
    }

    // Always allow /tmp write
    lines.push("(allow file-write* (subpath \"/tmp\"))".into());
    lines.push("(allow file-write* (subpath \"/private/tmp\"))".into());
    lines.push("(allow file-write* (subpath \"/var/folders\"))".into());
    lines.push("(allow file-write* (subpath \"/private/var/folders\"))".into());

    match policy.network.mode {
        NetworkMode::None => {
            lines.push("(deny network*)".into());
        }
        NetworkMode::Allowlist => {
            // Fail closed at the kernel: only localhost (the userspace proxy).
            // Host allowlisting is the proxy's job; do not grant general outbound.
            lines.push("(allow network* (remote ip \"localhost:*\"))".into());
            lines.push("(allow network-bind (local ip \"localhost:*\"))".into());
        }
        NetworkMode::Unrestricted => {
            lines.push("(allow network*)".into());
        }
    }

    Ok(lines.join("\n") + "\n")
}

fn resolve_path(p: &str, workdir: &Path) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        workdir.join(path)
    }
}

fn apply_rlimits(policy: &sandbox_policy::SandboxPolicy) -> Result<(), MechanismError> {
    let mem = policy
        .resources
        .memory_bytes()
        .map_err(|e| MechanismError::Message(e.to_string()))? as rlim_t;
    // Soft data / RSS limits (best-effort on macOS; RLIMIT_AS is often rejected).
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: mem,
            rlim_max: mem,
        };
        #[cfg(target_os = "macos")]
        {
            // RLIMIT_RSS exists on Darwin as a soft hint.
            const RLIMIT_RSS: u32 = 5;
            if setrlimit(RLIMIT_RSS as i32, &lim) != 0 {
                tracing::debug!("setrlimit(RLIMIT_RSS) unavailable — continuing without RSS cap");
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            if setrlimit(RLIMIT_AS, &lim) != 0 {
                warn!("setrlimit(RLIMIT_AS) failed — continuing without AS cap");
            }
            if setrlimit(RLIMIT_DATA, &lim) != 0 {
                warn!("setrlimit(RLIMIT_DATA) failed — continuing without DATA cap");
            }
        }
        // CPU seconds: rough mapping from cpus (not perfect)
        let cpu_secs = (policy.resources.cpus * 3600.0).ceil() as rlim_t; // 1h * cpus
        let clim = libc::rlimit {
            rlim_cur: cpu_secs.max(60),
            rlim_max: cpu_secs.max(60),
        };
        if setrlimit(RLIMIT_CPU, &clim) != 0 {
            warn!("setrlimit(RLIMIT_CPU) failed");
        }
    }
    Ok(())
}

fn write_profile(contents: &str) -> Result<NamedTempFile, MechanismError> {
    let mut f = NamedTempFile::new().map_err(|e| MechanismError::Message(e.to_string()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| MechanismError::Message(e.to_string()))?;
    f.flush()
        .map_err(|e| MechanismError::Message(e.to_string()))?;
    Ok(f)
}

fn spawn_sandboxed(
    profile_path: &Path,
    policy: &sandbox_policy::SandboxPolicy,
    workdir: &Path,
    command: &[String],
    env: &[(String, String)],
    tty: bool,
) -> Result<std::process::ExitStatus, MechanismError> {
    let sandbox_exec = which_sandbox_exec()
        .ok_or_else(|| MechanismError::Unavailable("sandbox-exec not found (macOS only)".into()))?;

    let mut argv: Vec<String> = vec![
        sandbox_exec.display().to_string(),
        "-f".into(),
        profile_path.display().to_string(),
    ];
    if command.is_empty() {
        argv.push("/bin/zsh".into());
        argv.push("-i".into());
    } else {
        argv.extend(command.iter().cloned());
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.current_dir(workdir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if policy.network.mode == NetworkMode::Allowlist {
        if let Ok(port) = std::env::var("SSBX_PROXY_PORT") {
            let url = format!("http://127.0.0.1:{port}");
            cmd.env("HTTP_PROXY", &url);
            cmd.env("HTTPS_PROXY", &url);
            cmd.env("http_proxy", &url);
            cmd.env("https_proxy", &url);
            cmd.env("NO_PROXY", "localhost,127.0.0.1");
        }
    }

    // Apply rlimits in the child before exec via pre_exec
    let policy_for_child = policy.clone();
    unsafe {
        cmd.pre_exec(move || {
            let _ = apply_rlimits(&policy_for_child);
            Ok(())
        });
    }

    if tty {
        cmd.stdin(Stdio::inherit());
    }
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    info!(?argv, "mac seatbelt spawn");
    let status = cmd
        .status()
        .map_err(|e| MechanismError::Message(format!("sandbox-exec failed: {e}")))?;
    Ok(status)
}

impl Mechanism for MacMechanism {
    fn kind(&self) -> MechanismKind {
        MechanismKind::Mac
    }

    fn name(&self) -> &'static str {
        "mac_seatbelt"
    }

    fn doctor(&self) -> Vec<DoctorItem> {
        let mut items = Vec::new();
        let available = Self::sandbox_exec_available();
        items.push(DoctorItem {
            name: "sandbox-exec".into(),
            ok: available,
            detail: if available {
                which_sandbox_exec()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            } else {
                "not found — macOS host required".into()
            },
        });
        items.push(DoctorItem {
            name: "platform".into(),
            ok: cfg!(target_os = "macos"),
            detail: std::env::consts::OS.into(),
        });
        items.push(DoctorItem {
            name: "rlimits".into(),
            ok: true,
            detail: "setrlimit AS/DATA/CPU (soft; weaker than Linux cgroups)".into(),
        });
        items
    }

    fn create(&self, req: &CreateRequest) -> Result<CreateResult, MechanismError> {
        if !cfg!(target_os = "macos") {
            return Err(MechanismError::Unavailable(
                "mac_seatbelt requires macOS".into(),
            ));
        }

        let profile = generate_seatbelt_profile(&req.policy, &req.workdir)?;
        let profile_file = write_profile(&profile)?;

        if req.ephemeral || !req.command.is_empty() {
            let status = spawn_sandboxed(
                profile_file.path(),
                &req.policy,
                &req.workdir,
                &req.command,
                &req.env,
                true,
            )?;
            return Ok(CreateResult {
                name: req.name.clone(),
                mechanism: MechanismKind::Mac,
                runtime_id: format!("mac-ephemeral:{}", req.name),
                proxy_port: std::env::var("SSBX_PROXY_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok()),
                log_path: None,
                exit_code: status.code(),
            });
        }

        // Persistent mac sandbox: keep profile on disk for later exec
        let base = self.state_dir.clone().unwrap_or_else(dirs_fallback);
        let dir = base.join("instances").join(&req.name);
        fs::create_dir_all(&dir).map_err(|e| MechanismError::Message(e.to_string()))?;
        let profile_path = dir.join("profile.sb");
        fs::write(&profile_path, &profile).map_err(|e| MechanismError::Message(e.to_string()))?;
        fs::write(dir.join("workdir"), req.workdir.display().to_string())
            .map_err(|e| MechanismError::Message(e.to_string()))?;
        if let Ok(yaml) = serde_yaml::to_string(&req.policy) {
            let _ = fs::write(dir.join("policy.yaml"), yaml);
        }

        Ok(CreateResult {
            name: req.name.clone(),
            mechanism: MechanismKind::Mac,
            runtime_id: format!("mac:{}", profile_path.display()),
            proxy_port: std::env::var("SSBX_PROXY_PORT")
                .ok()
                .and_then(|p| p.parse().ok()),
            log_path: None,
            exit_code: None,
        })
    }

    fn exec(&self, req: &ExecRequest) -> Result<ExecResult, MechanismError> {
        let (profile_path, workdir) = parse_mac_runtime(&req.runtime_id)?;
        let policy = profile_path
            .parent()
            .map(|dir| dir.join("policy.yaml"))
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|yaml| serde_yaml::from_str(&yaml).ok())
            .unwrap_or_else(sandbox_policy::SandboxPolicy::default);
        let status = spawn_sandboxed(
            &profile_path,
            &policy,
            &workdir,
            &req.command,
            &req.env,
            req.tty,
        )?;
        Ok(ExecResult { status })
    }

    fn remove(&self, runtime_id: &str) -> Result<(), MechanismError> {
        if let Ok((profile_path, _)) = parse_mac_runtime(runtime_id) {
            if let Some(dir) = profile_path.parent() {
                let _ = fs::remove_dir_all(dir);
            }
        }
        Ok(())
    }
}

fn dirs_fallback() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("simple-sandbox")
}

fn parse_mac_runtime(runtime_id: &str) -> Result<(PathBuf, PathBuf), MechanismError> {
    if let Some(path) = runtime_id.strip_prefix("mac:") {
        let profile_path = PathBuf::from(path);
        let dir = profile_path
            .parent()
            .ok_or_else(|| MechanismError::Message("invalid mac runtime id".into()))?;
        let workdir = fs::read_to_string(dir.join("workdir"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        return Ok((profile_path, workdir));
    }
    Err(MechanismError::Message(format!(
        "not a mac runtime id: {runtime_id}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_policy::SandboxPolicy;

    #[test]
    fn profile_contains_workdir_and_deny_network() {
        let policy = SandboxPolicy::default();
        let profile = generate_seatbelt_profile(&policy, Path::new("/tmp")).unwrap();
        assert!(profile.contains("deny default"));
        assert!(profile.contains("deny network"));
        assert!(profile.contains("allow file-write*"));
    }
}
