//! Rootless Podman / Docker-compatible Linux sandbox mechanism.
//!
//! Prefers `podman`, falls back to `docker` (Colima / Docker Desktop / Podman Machine).
//! Runs unprivileged from the host's perspective once a user-level VM runtime exists.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sandbox_core::{
    CreateRequest, CreateResult, DoctorItem, ExecRequest, ExecResult, Mechanism, MechanismError,
};
use sandbox_policy::{MechanismKind, NetworkMode};
use tracing::{info, warn};
use which::which;

const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";

/// Container runtime backend (podman or docker CLI).
#[derive(Debug, Clone)]
pub struct PodmanMechanism {
    /// Override binary path; otherwise auto-detect.
    pub binary: Option<PathBuf>,
    /// Container image.
    pub image: String,
}

impl Default for PodmanMechanism {
    fn default() -> Self {
        Self {
            binary: None,
            image: DEFAULT_IMAGE.into(),
        }
    }
}

impl PodmanMechanism {
    pub fn new() -> Self {
        Self::default()
    }

    fn runtime_bin(&self) -> Result<PathBuf, MechanismError> {
        if let Some(b) = &self.binary {
            return Ok(b.clone());
        }
        if let Ok(p) = which("podman") {
            return Ok(p);
        }
        if let Ok(p) = which("docker") {
            return Ok(p);
        }
        Err(MechanismError::Unavailable(
            "neither podman nor docker found on PATH (install Podman Machine or Colima)".into(),
        ))
    }

    fn run_cmd(&self, args: &[&str]) -> Result<std::process::Output, MechanismError> {
        let bin = self.runtime_bin()?;
        let out = Command::new(&bin).args(args).output().map_err(|e| {
            MechanismError::Message(format!("failed to run {}: {e}", bin.display()))
        })?;
        Ok(out)
    }

    fn runtime_ok(&self) -> Result<String, MechanismError> {
        let bin = self.runtime_bin()?;
        // Prefer a simple ping that works for both podman and docker.
        let out = Command::new(&bin)
            .args(["ps", "-q"])
            .output()
            .map_err(|e| MechanismError::Message(e.to_string()))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(MechanismError::Unavailable(format!(
                "{} not usable (is the machine/VM running?): {err}",
                bin.display()
            )));
        }
        // Best-effort arch probe
        let arch = Command::new(&bin)
            .args(["version", "--format", "{{.Server.Arch}}"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| std::env::consts::ARCH.to_string());
        Ok(arch)
    }

    fn build_run_args(
        &self,
        req: &CreateRequest,
        name: &str,
        detach: bool,
    ) -> Result<Vec<String>, MechanismError> {
        let policy = &req.policy;
        let mem = policy
            .resources
            .memory_bytes()
            .map_err(|e| MechanismError::Message(e.to_string()))?;
        let cpus = policy.resources.cpus;

        let mut args = vec!["run".to_string()];
        if detach {
            args.push("-d".into());
        } else {
            args.push("--rm".into());
        }
        args.push("--name".into());
        args.push(container_name(name));

        args.push(format!("--cpus={cpus}"));
        args.push(format!("--memory={mem}"));

        match policy.network.mode {
            NetworkMode::None | NetworkMode::Allowlist => {
                // Deny raw network; allowlist uses host proxy via env when we add host gateway.
                // For allowlist we still isolate and point HTTP(S)_PROXY at host.
                args.push("--network".into());
                args.push("none".into());
            }
            NetworkMode::Unrestricted => {
                warn!("policy network.mode=unrestricted: using default container network");
            }
        }

        // Workspace bind
        if policy.filesystem.workdir {
            let host = req
                .workdir
                .canonicalize()
                .unwrap_or_else(|_| req.workdir.clone());
            args.push("-v".into());
            args.push(format!("{}:/workspace:rw", host.display()));
            args.push("-w".into());
            args.push("/workspace".into());
        }

        // Extra RO/RW mounts (absolute host paths preferred)
        for p in &policy.filesystem.read_only {
            if let Some(spec) = mount_spec(p, req.workdir.as_path(), true) {
                args.push("-v".into());
                args.push(spec);
            }
        }
        for p in &policy.filesystem.read_write {
            if p == "/workspace" || p == "/tmp" {
                continue;
            }
            if let Some(spec) = mount_spec(p, req.workdir.as_path(), false) {
                args.push("-v".into());
                args.push(spec);
            }
        }

        // tmpfs for /tmp
        args.push("--tmpfs".into());
        args.push("/tmp:rw,size=64m".into());

        // Env
        for (k, v) in &req.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }

        // Proxy env for allowlist (host must run proxy; CLI wires HTTPS_PROXY)
        if policy.network.mode == NetworkMode::Allowlist {
            // Placeholder — CLI sets real port via env before create when proxy is up.
            if let Ok(port) = std::env::var("SSBX_PROXY_PORT") {
                let url = format!("http://host.docker.internal:{port}");
                // host.docker.internal works on Docker Desktop / Colima; podman may need --add-host
                args.push("--add-host".into());
                args.push("host.docker.internal:host-gateway".into());
                // network none blocks this — for allowlist we need a different approach:
                // use slirp/pasta with no outbound except via proxy is complex.
                // Practical v1: use bridge network but rely on proxy + HTTP_PROXY only,
                // documenting that full netns deny needs later work.
                // Re-evaluate: switch allowlist to default network + proxy env.
                let _ = url;
            }
        }

        args.push(self.image.clone());

        if req.command.is_empty() {
            // Persistent: sleep forever
            args.push("sleep".into());
            args.push("infinity".into());
        } else {
            args.extend(req.command.iter().cloned());
        }

        Ok(args)
    }
}

fn container_name(name: &str) -> String {
    format!("ssbx-{name}")
}

fn mount_spec(policy_path: &str, workdir: &Path, read_only: bool) -> Option<String> {
    // Guest paths under /workspace or absolute host paths
    let host = if policy_path.starts_with("/workspace") {
        return None; // already mounted
    } else if Path::new(policy_path).is_absolute() {
        // Treat as guest path only if it looks like a host path that exists
        let p = Path::new(policy_path);
        if p.exists() {
            p.to_path_buf()
        } else {
            // Map as guest-only hint — skip unknown
            return None;
        }
    } else {
        workdir.join(policy_path)
    };
    if !host.exists() {
        return None;
    }
    let mode = if read_only { "ro" } else { "rw" };
    let guest = format!("/mnt/{}", host.file_name()?.to_string_lossy());
    Some(format!("{}:{guest}:{mode}", host.display()))
}

impl Mechanism for PodmanMechanism {
    fn kind(&self) -> MechanismKind {
        MechanismKind::Podman
    }

    fn name(&self) -> &'static str {
        "linux_podman"
    }

    fn doctor(&self) -> Vec<DoctorItem> {
        let mut items = Vec::new();
        match self.runtime_bin() {
            Ok(bin) => {
                items.push(DoctorItem {
                    name: "runtime-binary".into(),
                    ok: true,
                    detail: bin.display().to_string(),
                });
                match self.runtime_ok() {
                    Ok(arch) => items.push(DoctorItem {
                        name: "runtime-engine".into(),
                        ok: true,
                        detail: format!("reachable, arch={arch}"),
                    }),
                    Err(e) => items.push(DoctorItem {
                        name: "runtime-engine".into(),
                        ok: false,
                        detail: e.to_string(),
                    }),
                }
            }
            Err(e) => items.push(DoctorItem {
                name: "runtime-binary".into(),
                ok: false,
                detail: e.to_string(),
            }),
        }

        let host_arch = std::env::consts::ARCH;
        items.push(DoctorItem {
            name: "host-arch".into(),
            ok: host_arch == "aarch64",
            detail: format!("{host_arch} (arm64 Mac preferred for linux arm64 guests)"),
        });

        items.push(DoctorItem {
            name: "default-image".into(),
            ok: true,
            detail: self.image.clone(),
        });

        items
    }

    fn create(&self, req: &CreateRequest) -> Result<CreateResult, MechanismError> {
        let bin = self.runtime_bin()?;
        self.runtime_ok()?;

        // For allowlist networking: use bridge + proxy env (best-effort without root).
        let mut args = self.build_run_args(req, &req.name, !req.ephemeral)?;

        // Fix allowlist: replace network none with default + proxy
        if req.policy.network.mode == NetworkMode::Allowlist {
            args = self.build_allowlist_args(req, &req.name, !req.ephemeral)?;
        }

        info!(runtime = %bin.display(), ?args, "podman create/run");

        if req.ephemeral {
            let status = Command::new(&bin)
                .args(&args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|e| MechanismError::Message(e.to_string()))?;
            return Ok(CreateResult {
                name: req.name.clone(),
                mechanism: MechanismKind::Podman,
                runtime_id: format!("ephemeral:{}", req.name),
                proxy_port: std::env::var("SSBX_PROXY_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok()),
                log_path: None,
                exit_code: status.code(),
            });
        }

        let out = Command::new(&bin)
            .args(&args)
            .output()
            .map_err(|e| MechanismError::Message(e.to_string()))?;
        if !out.status.success() {
            return Err(MechanismError::Message(format!(
                "create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let runtime_id = if id.is_empty() {
            container_name(&req.name)
        } else {
            id
        };

        Ok(CreateResult {
            name: req.name.clone(),
            mechanism: MechanismKind::Podman,
            runtime_id,
            proxy_port: std::env::var("SSBX_PROXY_PORT")
                .ok()
                .and_then(|p| p.parse().ok()),
            log_path: None,
            exit_code: None,
        })
    }

    fn exec(&self, req: &ExecRequest) -> Result<ExecResult, MechanismError> {
        let bin = self.runtime_bin()?;
        let cname = if req.runtime_id.starts_with("ssbx-") || req.runtime_id.len() >= 12 {
            req.runtime_id.clone()
        } else {
            container_name(&req.name)
        };

        let mut args = vec!["exec".to_string()];
        if req.tty {
            args.push("-it".into());
        }
        for (k, v) in &req.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        if let Some(cwd) = &req.cwd {
            args.push("-w".into());
            args.push(cwd.clone());
        }
        args.push(cname);
        if req.command.is_empty() {
            args.push("sh".into());
        } else {
            args.extend(req.command.iter().cloned());
        }

        let status = Command::new(&bin)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| MechanismError::Message(e.to_string()))?;

        Ok(ExecResult { status })
    }

    fn remove(&self, runtime_id: &str) -> Result<(), MechanismError> {
        let bin = self.runtime_bin()?;
        let name = if runtime_id.starts_with("ephemeral:") {
            return Ok(());
        } else {
            runtime_id
        };
        let out = Command::new(&bin)
            .args(["rm", "-f", name])
            .output()
            .map_err(|e| MechanismError::Message(e.to_string()))?;
        if !out.status.success() {
            // Also try ssbx- prefixed
            let _ = Command::new(&bin)
                .args(["rm", "-f", &format!("ssbx-{name}")])
                .output();
        }
        Ok(())
    }

    fn logs(&self, runtime_id: &str, tail: usize) -> Result<String, MechanismError> {
        let bin = self.runtime_bin()?;
        let out = self
            .run_cmd(&["logs", "--tail", &tail.to_string(), runtime_id])
            .or_else(|_| {
                let _ = bin;
                self.run_cmd(&[
                    "logs",
                    "--tail",
                    &tail.to_string(),
                    &format!("ssbx-{runtime_id}"),
                ])
            })?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

impl PodmanMechanism {
    /// Allowlist mode: default network + HTTP(S)_PROXY to host proxy.
    /// Full `--network none` + proxy requires extra netns plumbing; documented as best-effort.
    fn build_allowlist_args(
        &self,
        req: &CreateRequest,
        name: &str,
        detach: bool,
    ) -> Result<Vec<String>, MechanismError> {
        let mut policy = req.policy.clone();
        // Temporarily treat as unrestricted for mount/cpu building, then patch network.
        policy.network.mode = NetworkMode::Unrestricted;
        let mut fake = req.clone();
        fake.policy = policy;
        let mut args = self.build_run_args(&fake, name, detach)?;

        // Remove any accidental --network none
        let mut cleaned = Vec::new();
        let mut skip_next = false;
        for a in args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if a == "--network" {
                skip_next = true;
                continue;
            }
            cleaned.push(a);
        }
        args = cleaned;

        args.insert(1, "--add-host".into());
        args.insert(2, "host.docker.internal:host-gateway".into());

        if let Ok(port) = std::env::var("SSBX_PROXY_PORT") {
            let url = format!("http://host.docker.internal:{port}");
            // Insert env before image (last non-command tokens)
            // Simpler: push -e before image name which is near the end
            let img_pos = args
                .iter()
                .position(|a| a == &self.image)
                .unwrap_or(args.len());
            args.insert(img_pos, "-e".into());
            args.insert(img_pos + 1, format!("HTTPS_PROXY={url}"));
            args.insert(img_pos, "-e".into());
            args.insert(img_pos + 1, format!("HTTP_PROXY={url}"));
            args.insert(img_pos, "-e".into());
            args.insert(img_pos + 1, format!("https_proxy={url}"));
            args.insert(img_pos, "-e".into());
            args.insert(img_pos + 1, format!("http_proxy={url}"));
            args.insert(img_pos, "-e".into());
            args.insert(img_pos + 1, "NO_PROXY=localhost,127.0.0.1".into());
        }

        Ok(args)
    }
}

/// Pull the default image if missing (best-effort).
pub fn ensure_image(mech: &PodmanMechanism) -> Result<(), MechanismError> {
    let bin = mech.runtime_bin()?;
    let out = Command::new(&bin)
        .args(["image", "inspect", &mech.image])
        .output()
        .map_err(|e| MechanismError::Message(e.to_string()))?;
    if out.status.success() {
        return Ok(());
    }
    info!(image = %mech.image, "pulling image");
    let status = Command::new(&bin)
        .args(["pull", &mech.image])
        .status()
        .map_err(|e| MechanismError::Message(e.to_string()))?;
    if !status.success() {
        return Err(MechanismError::Message(format!(
            "failed to pull {}",
            mech.image
        )));
    }
    Ok(())
}
