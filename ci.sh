#!/usr/bin/env bash
set -euo pipefail
echo "Running CI for simple-sandbox..."
echo "==> fmt"
cargo fmt --all -- --check
echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings
echo "==> test"
cargo test --workspace
echo "CI completed successfully!"
