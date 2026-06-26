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
  <img src="https://img.shields.io/badge/status-coming%20soon-yellow.svg" alt="coming soon">
  <img src="https://img.shields.io/badge/for-AI%20agents-blueviolet.svg" alt="for AI agents">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="license">
</p>

> **⚠ Coming soon.**

> Part of [**simple tools**](https://zeta1999.github.io/renoir42/simple-tools.html) — small, composable Rust libraries for building tooling fast from a harness.

---

## Idea

When a harness lets a model run tools, you want a boundary around the blast radius. `simple-sandbox` is that boundary: explicit mediation of the resources a tool can touch, paired with [`limited-shell`](https://github.com/zeta1999/limited-shell-public)'s capability model so that *what can run* and *what it can reach* are both scoped.

## License

MIT OR Apache-2.0
