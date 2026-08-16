<p align="center">
  <img src="assets/logo.svg" alt="simple-sandbox" width="150"/>
</p>

<h1 align="center">simple-sandbox</h1>

<p align="center">
  <strong>A sandbox for AI agents and the tools they run — contain side effects, mediate access, keep a trail.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/part%20of-simple%20tools-00d4ff.svg" alt="part of simple tools">
  <img src="https://img.shields.io/badge/Rust-2021-orange.svg?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="alpha">
  <img src="https://img.shields.io/badge/for-AI%20agents-blueviolet.svg" alt="for AI agents">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="license">
</p>

> **⚠ Alpha.** `network.mode: none` is the real boundary. Allowlist is proxy-mediated.

Agent-ready sandbox CLI (`ssbx`) for containing AI agent side effects.

Part of [simple tools](https://zeta1999.github.io/renoir42/simple-tools.html).

## Status

Mac-first v1:

- **`mac_seatbelt`** — `sandbox-exec` + `setrlimit`, no sudo
- **`linux_podman`** — rootless Podman / Docker (Colima / Podman Machine) for Linux arm64 guests on Mac
- **`linux_libkrun`** — stub for later

**Later (not yet):** Linux-on-Linux with rootless Podman **and** bubblewrap.

## Build

Requires sibling checkouts next to this repo:

- `../limited-shell`
- `../rust-secure-memory`
- `../simple-network` (workspace dep; used for future supervisor channel)

**Allowlist caveat:** Mac seatbelt only permits localhost (the userspace CONNECT proxy). Podman allowlist is still honor-system (`HTTP(S)_PROXY` on a bridge network) — use `network.mode: none` when you need a real boundary.

```bash
cargo build -p ssbx
cargo test --workspace
```

## Quick start (macOS)

```bash
# Check mechanisms
cargo run -p ssbx -- doctor

# Ephemeral run with seatbelt (default fallback when podman is unavailable)
cargo run -p ssbx -- run --mechanism mac --policy examples/policies/deny-all.yaml -- /bin/echo hello

# Persistent sandbox
cargo run -p ssbx -- create --name demo --mechanism mac --policy examples/policies/workspace-rw.yaml
cargo run -p ssbx -- exec demo -- /bin/ls
cargo run -p ssbx -- rm demo
```

## Policy

See `examples/policies/`. Schema:

```yaml
version: 1
filesystem:
  workdir: true
  read_only: []
  read_write: ["/workspace", "/tmp"]
network:
  mode: none          # none | allowlist | unrestricted
  endpoints:
    - { host: api.github.com, port: 443 }
resources:
  cpus: 2
  memory: 2G
mechanism: auto       # podman | mac | krun | auto
secrets:
  - { env: TOKEN, from: "env:MY_TOKEN" }
```

Resource preflight uses `limited-core` extent pools. Secrets are held in `secure-memory` `LockedBuffer` until injected as child env.

## CLI

```
ssbx create [--name N] [--policy FILE] [--mechanism podman|mac|krun|auto] [--cpus N] [--memory SIZE]
ssbx run    [--policy FILE] [--mechanism ...] -- CMD...
ssbx exec   [name] -- CMD...
ssbx shell  [name]
ssbx policy get|set [name] [--policy FILE]
ssbx ls | rm <name> | logs [name]
ssbx doctor [--json]
```

State lives under `~/.config/simple-sandbox/` (override with `--config` / `SSBX_CONFIG`).

## License

MIT OR Apache-2.0
