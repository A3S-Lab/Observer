#!/usr/bin/env bash
# End-to-end smoke test for a3s-observer. Run on a Linux box with root (CAP_BPF) + the eBPF
# toolchain (nightly + rust-src + bpf-linker). Builds, loads the probes, drives one LLM call,
# and checks an event flows. Exits non-zero on failure. CI can't run this (needs a real
# kernel + root); it makes the manual validation reproducible.
#
#   sudo ./scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# rustup installs to ~/.cargo/bin; make this work in a non-login shell too.
command -v cargo >/dev/null || { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; }

echo "== lib + parser unit tests =="
cargo test -p a3s-observer -p a3s-observer-common

echo "== build collector (compiles the eBPF crate) =="
cargo build --release -p a3s-observer-collector
bin=target/release/a3s-observer-collector

echo "== --version =="
"$bin" --version

echo "== run + drive one LLM call (need root) =="
log=$(mktemp)
RUST_LOG=info A3S_OBSERVER_JSON=1 timeout -s INT 8 "$bin" >"$log" 2>&1 &
pid=$!
sleep 3
curl -s -o /dev/null --max-time 4 https://api.anthropic.com/ 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo "== checks =="
grep -q "probes attached" "$log" || { echo "FAIL: probes did not attach"; cat "$log"; rm -f "$log"; exit 1; }
grep -aq '"event"' "$log" || { echo "FAIL: no events captured"; rm -f "$log"; exit 1; }
echo "PASS: probes attached and events flowed"
rm -f "$log"
