# simple-sandbox

> **Status: coming soon.**

A sandbox for AI agents and the tools they run. Contain side effects, mediate filesystem and network access, and keep an audit trail of what the agent actually did.

Part of [**simple tools**](https://zeta1999.github.io/renoir42/simple-tools.html) — small, composable Rust libraries for building tooling fast from a harness.

## Idea

When a harness lets a model run tools, you want a boundary around the blast radius. `simple-sandbox` is that boundary: explicit mediation of the resources a tool can touch, paired with [`limited-shell`](https://github.com/zeta1999/limited-shell-public)'s capability model so that *what can run* and *what it can reach* are both scoped.

## License

MIT OR Apache-2.0
