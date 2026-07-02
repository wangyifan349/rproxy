#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] checking source formatting"
cargo fmt --check

echo "[2/4] running release-mode semantic check with verbose output"
cargo check --release --verbose

echo "[3/4] running clippy with warnings denied"
cargo clippy --release --all-targets --all-features --verbose -- -D warnings

echo "[4/4] building optimized release binary"
cargo build --release --verbose

echo "[done] build completed. Start the server with: ./target/release/rproxy"
