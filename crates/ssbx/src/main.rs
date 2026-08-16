//! `ssbx` — agent-ready sandbox CLI.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sandbox_core::{
    default_config_dir, resolve_mechanism, resolve_secrets, CreateRequest, ExecRequest, Mechanism,
    Store,
};
use sandbox_mech_krun::KrunMechanism;
use sandbox_mech_mac::MacMechanism;
use sandbox_mech_podman::{ensure_image, PodmanMechanism};
use sandbox_policy::{preflight, HostCapacity, MechanismKind, NetworkMode, SandboxPolicy};
use sandbox_proxy::{allow_from_endpoints, start_allowlist_proxy};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ssbx", version, about = "Agent-ready sandbox CLI")]
struct Cli {
    /// Config / state directory
    #[arg(long, global = true, env = "SSBX_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a persistent sandbox
    Create {
        #[arg(long, short)]
        name: Option<String>,
        #[arg(long, short)]
        policy: Option<PathBuf>,
        #[arg(long, short = 'm', value_enum)]
        mechanism: Option<MechArg>,
        #[arg(long)]
        cpus: Option<f64>,
        #[arg(long)]
        memory: Option<String>,
    },
    /// Run a command ephemerally inside a sandbox
    Run {
        #[arg(long, short)]
        policy: Option<PathBuf>,
        #[arg(long, short = 'm', value_enum)]
        mechanism: Option<MechArg>,
        #[arg(long)]
        cpus: Option<f64>,
        #[arg(long)]
        memory: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Exec a command in an existing sandbox
    Exec {
        name: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Interactive shell in an existing sandbox
    Shell { name: Option<String> },
    /// Get or set sandbox policy
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// List sandboxes
    Ls,
    /// Remove a sandbox
    Rm { name: String },
    /// Show sandbox logs
    Logs {
        name: Option<String>,
        #[arg(long, default_value_t = 100)]
        tail: usize,
    },
    /// Check host / mechanism readiness
    Doctor {
        #[arg(long, short = 'm', value_enum)]
        mechanism: Option<MechArg>,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    Get {
        name: Option<String>,
    },
    Set {
        name: Option<String>,
        #[arg(long, short)]
        policy: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MechArg {
    Podman,
    Mac,
    Krun,
    Auto,
}

impl From<MechArg> for MechanismKind {
    fn from(v: MechArg) -> Self {
        match v {
            MechArg::Podman => MechanismKind::Podman,
            MechArg::Mac => MechanismKind::Mac,
            MechArg::Krun => MechanismKind::Krun,
            MechArg::Auto => MechanismKind::Auto,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<u8> {
    let cli = Cli::parse();
    let config = cli.config.unwrap_or_else(default_config_dir);
    let store = Store::open(&config)?;

    match cli.command {
        Commands::Doctor { mechanism } => {
            cmd_doctor(&config, mechanism.map(Into::into), cli.json)?;
            Ok(0)
        }
        Commands::Create {
            name,
            policy,
            mechanism,
            cpus,
            memory,
        } => {
            cmd_create(
                &store,
                name,
                policy,
                mechanism.map(Into::into),
                cpus,
                memory,
                cli.json,
            )
            .await?;
            Ok(0)
        }
        Commands::Run {
            policy,
            mechanism,
            cpus,
            memory,
            name,
            command,
        } => {
            cmd_run(
                &store,
                name,
                policy,
                mechanism.map(Into::into),
                cpus,
                memory,
                command,
            )
            .await
        }
        Commands::Exec { name, command } => cmd_exec(&store, name.as_deref(), command),
        Commands::Shell { name } => {
            let shell = if cfg!(target_os = "macos") {
                vec!["/bin/zsh".into(), "-i".into()]
            } else {
                vec!["/bin/sh".into(), "-i".into()]
            };
            // For podman use sh inside container
            let rec = store.get_or_last(name.as_deref())?;
            let command = if rec.mechanism == MechanismKind::Podman {
                vec!["sh".into(), "-i".into()]
            } else {
                shell
            };
            cmd_exec(&store, name.as_deref(), command)
        }
        Commands::Policy { action } => {
            cmd_policy(&store, action, cli.json)?;
            Ok(0)
        }
        Commands::Ls => {
            cmd_ls(&store, cli.json)?;
            Ok(0)
        }
        Commands::Rm { name } => {
            cmd_rm(&store, &name)?;
            Ok(0)
        }
        Commands::Logs { name, tail } => {
            cmd_logs(&store, name.as_deref(), tail)?;
            Ok(0)
        }
    }
}

fn mech_box(kind: MechanismKind, config_root: &std::path::Path) -> Result<Arc<dyn Mechanism>> {
    let kind = resolve_mechanism(kind);
    Ok(match kind {
        MechanismKind::Podman | MechanismKind::Auto => Arc::new(PodmanMechanism::new()),
        MechanismKind::Mac => Arc::new(MacMechanism {
            state_dir: Some(config_root.join("mac")),
        }),
        MechanismKind::Krun => Arc::new(KrunMechanism::new()),
    })
}

fn load_policy(
    path: Option<PathBuf>,
    cpus: Option<f64>,
    memory: Option<String>,
    mechanism: Option<MechanismKind>,
) -> Result<SandboxPolicy> {
    let mut policy = if let Some(p) = path {
        SandboxPolicy::load_file(&p).with_context(|| format!("load policy {}", p.display()))?
    } else {
        SandboxPolicy::restrictive_default()
    };
    if let Some(c) = cpus {
        policy.resources.cpus = c;
    }
    if let Some(m) = memory {
        policy.resources.memory = m;
    }
    if let Some(m) = mechanism {
        policy.mechanism = Some(m);
    }
    policy.validate()?;
    Ok(policy)
}

fn host_capacity() -> HostCapacity {
    // Best-effort; conservative defaults are fine for preflight.
    HostCapacity::default()
}

async fn maybe_start_proxy(policy: &SandboxPolicy) -> Result<Option<sandbox_proxy::ProxyHandle>> {
    if policy.network.mode != NetworkMode::Allowlist {
        return Ok(None);
    }
    let allow = allow_from_endpoints(
        policy
            .network
            .endpoints
            .iter()
            .map(|e| (e.host.clone(), e.port)),
    );
    let handle = start_allowlist_proxy(allow).await?;
    std::env::set_var("SSBX_PROXY_PORT", handle.port().to_string());
    Ok(Some(handle))
}

async fn cmd_create(
    store: &Store,
    name: Option<String>,
    policy_path: Option<PathBuf>,
    mechanism: Option<MechanismKind>,
    cpus: Option<f64>,
    memory: Option<String>,
    json: bool,
) -> Result<()> {
    let name = name.unwrap_or_else(|| "default".into());
    let mut policy = load_policy(policy_path, cpus, memory, mechanism)?;
    let kind = resolve_mechanism(policy.mechanism_or_auto());
    policy.mechanism = Some(kind);
    preflight(&policy, &host_capacity())?;

    let secrets = resolve_secrets(&policy.secrets, &std::env::current_dir()?)?;
    let env = secrets.to_env_pairs()?;

    let _proxy = maybe_start_proxy(&policy).await?;
    let mech = mech_box(kind, store.root())?;
    if kind == MechanismKind::Podman {
        let _ = ensure_image(&PodmanMechanism::new());
    }

    let workdir = std::env::current_dir()?;
    let req = CreateRequest {
        name: name.clone(),
        policy: policy.clone(),
        workdir: workdir.clone(),
        ephemeral: false,
        command: Vec::new(),
        env,
    };
    let result = mech.create(&req)?;
    let mut rec = Store::new_record(
        &name,
        kind,
        &result.runtime_id,
        &policy,
        &workdir,
        false,
        result.proxy_port,
    )?;
    rec.log_path = Some(store.log_path_for(&name));
    store.save_policy(&name, &policy)?;
    store.insert(rec)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "created sandbox '{name}' via {} ({})",
            mech.name(),
            result.runtime_id
        );
    }
    Ok(())
}

async fn cmd_run(
    store: &Store,
    name: Option<String>,
    policy_path: Option<PathBuf>,
    mechanism: Option<MechanismKind>,
    cpus: Option<f64>,
    memory: Option<String>,
    command: Vec<String>,
) -> Result<u8> {
    let name = name.unwrap_or_else(|| format!("run-{}", &uuid_simple()));
    let mut policy = load_policy(policy_path, cpus, memory, mechanism)?;
    let kind = resolve_mechanism(policy.mechanism_or_auto());
    // On macOS prefer mac for quick local runs if podman unavailable
    let kind = prefer_available(kind)?;
    policy.mechanism = Some(kind);
    preflight(&policy, &host_capacity())?;

    let secrets = resolve_secrets(&policy.secrets, &std::env::current_dir()?)?;
    let env = secrets.to_env_pairs()?;

    let _proxy = maybe_start_proxy(&policy).await?;
    let mech = mech_box(kind, store.root())?;
    if kind == MechanismKind::Podman {
        let _ = ensure_image(&PodmanMechanism::new());
    }

    let workdir = std::env::current_dir()?;
    let req = CreateRequest {
        name: name.clone(),
        policy,
        workdir,
        ephemeral: true,
        command,
        env,
    };
    let result = mech.create(&req)?;
    let _ = store; // ephemeral — not stored
    Ok(result.exit_code.unwrap_or(0) as u8)
}

fn prefer_available(kind: MechanismKind) -> Result<MechanismKind> {
    let kind = resolve_mechanism(kind);
    if kind == MechanismKind::Podman {
        let podman = PodmanMechanism::new();
        let items = podman.doctor();
        let ok = items.iter().any(|i| i.name == "runtime-engine" && i.ok);
        if !ok && cfg!(target_os = "macos") {
            info!("podman/docker unavailable — falling back to mac_seatbelt");
            return Ok(MechanismKind::Mac);
        }
    }
    Ok(kind)
}

fn cmd_exec(store: &Store, name: Option<&str>, command: Vec<String>) -> Result<u8> {
    let rec = store.get_or_last(name)?;
    store.touch_last_used(&rec.name)?;
    let mech = mech_box(rec.mechanism, store.root())?;
    let req = ExecRequest {
        name: rec.name.clone(),
        runtime_id: rec.runtime_id.clone(),
        command,
        env: Vec::new(),
        tty: true,
        cwd: Some("/workspace".into()),
    };
    let result = mech.exec(&req)?;
    Ok(result.status.code().unwrap_or(1) as u8)
}

fn cmd_policy(store: &Store, action: PolicyCmd, json: bool) -> Result<()> {
    match action {
        PolicyCmd::Get { name } => {
            let rec = store.get_or_last(name.as_deref())?;
            let policy = store.load_policy(&rec.name)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            } else {
                print!("{}", policy.to_yaml()?);
            }
        }
        PolicyCmd::Set { name, policy } => {
            let rec = store.get_or_last(name.as_deref())?;
            let p = SandboxPolicy::load_file(&policy)?;
            preflight(&p, &host_capacity())?;
            store.update_policy(&rec.name, &p)?;
            println!("updated policy for '{}'", rec.name);
        }
    }
    Ok(())
}

fn cmd_ls(store: &Store, json: bool) -> Result<()> {
    let list = store.list()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&list)?);
    } else if list.is_empty() {
        println!("(no sandboxes)");
    } else {
        for s in list {
            println!(
                "{}\t{}\t{}\t{}",
                s.name,
                s.mechanism,
                &s.runtime_id[..s.runtime_id.len().min(16)],
                s.created_at.to_rfc3339()
            );
        }
    }
    Ok(())
}

fn cmd_rm(store: &Store, name: &str) -> Result<()> {
    let rec = store.remove(name)?;
    let mech = mech_box(rec.mechanism, store.root())?;
    mech.remove(&rec.runtime_id)?;
    println!("removed '{name}'");
    Ok(())
}

fn cmd_logs(store: &Store, name: Option<&str>, tail: usize) -> Result<()> {
    let rec = store.get_or_last(name)?;
    let mech = mech_box(rec.mechanism, store.root())?;
    let logs = mech.logs(&rec.runtime_id, tail)?;
    print!("{logs}");
    Ok(())
}

fn cmd_doctor(
    config: &std::path::Path,
    mechanism: Option<MechanismKind>,
    json: bool,
) -> Result<()> {
    let kinds = match mechanism {
        Some(m) => vec![resolve_mechanism(m)],
        None => vec![
            MechanismKind::Podman,
            MechanismKind::Mac,
            MechanismKind::Krun,
        ],
    };
    let mut all = Vec::new();
    for k in kinds {
        let mech = mech_box(k, config)?;
        for mut item in mech.doctor() {
            item.name = format!("{}/{}", mech.name(), item.name);
            all.push(item);
        }
    }
    // Future: linux-on-linux podman + bubblewrap
    all.push(sandbox_core::DoctorItem {
        name: "future/linux-bwrap".into(),
        ok: true,
        detail: "planned: linux host with rootless podman + bubblewrap (not in mac-first v1)"
            .into(),
    });

    if json {
        println!("{}", serde_json::to_string_pretty(&all)?);
    } else {
        for i in &all {
            let mark = if i.ok { "ok" } else { "FAIL" };
            println!("[{mark}] {}: {}", i.name, i.detail);
        }
    }
    Ok(())
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{t:x}")
}
