#!/usr/bin/env bash
# End-to-end smoke test for a3s-observer. Run on a Linux box with root (CAP_BPF) + the eBPF
# toolchain (nightly + rust-src + bpf-linker). Builds, loads the probes, drives one LLM call,
# and checks an event flows. Exits non-zero on failure. CI can't run this (needs a real
# kernel + root); it makes the manual validation reproducible.
#
#   ./scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Older instructions ran the whole script through sudo, which hides the invoking user's Rust
# toolchain and leaves root-owned build artifacts. Drop back to the original user; only the
# collector process below needs privileges to load eBPF programs.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  exec sudo -u "$SUDO_USER" -H "$0" "$@"
fi

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
log=/tmp/a3s-observer-smoke.log
: >"$log"
fail() {
  echo "FAIL: $1"
  tail -200 "$log"
  echo "Full log: $log"
  exit 1
}
sudo -E env RUST_LOG=info A3S_OBSERVER_JSON=1 timeout -s INT 30 "$bin" >"$log" 2>&1 &
pid=$!
for _ in $(seq 1 25); do
  grep -q "probes attached" "$log" && break
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
grep -q "probes attached" "$log" || {
  wait "$pid" 2>/dev/null || true
  fail "probes did not attach"
}
marker="observer-exec-v2-$$"
short_marker="$marker-short"
semantic_marker="$marker-semantic"
many_marker="$marker-many"
huge_marker="$marker-huge"
stress_marker="$marker-stress"
proc_tail_marker="$marker-proc-tail"

# Short argv remains compatible with the old capture path.
/usr/bin/printf '%s\n' "$short_marker" >/dev/null

# A normal long argument must be reconstructed losslessly.
long_arg=$(printf 'x%.0s' $(seq 1 600))
/usr/bin/printf '%s\n' "$marker-$long_arg" >/dev/null

# Put a security-relevant tail beyond the old 64-byte boundary without executing it.
semantic_prefix=$(printf 'A%.0s' $(seq 1 96))
/usr/bin/printf '%s\n' "$semantic_marker-$semantic_prefix-base64 -d | sh" >/dev/null

# Exceed the argument-count cap. The event must be emitted and explicitly marked truncated.
/usr/bin/printf '%s' "$many_marker" a02 a03 a04 a05 a06 a07 a08 a09 a10 a11 a12 a13 a14 >/dev/null

# Exceed the total argv-byte cap. Again, emit an explicitly truncated event, never a silent cut.
printf -v huge_arg '%*s' 9000 ''
huge_arg=${huge_arg// /z}
/usr/bin/printf '%s' "$huge_marker-$huge_arg" >/dev/null

# Keep a process alive long enough for the successful-exec commit to trigger `/proc` argv
# supplementation. The marker is beyond the 12-argument kernel cap, so it cannot appear unless the
# userspace supplement recovered the complete command line.
/usr/bin/python3 -c 'import time; time.sleep(1)' a03 a04 a05 a06 a07 a08 a09 a10 a11 a12 "$proc_tail_marker"

# Exercise reassembly under a short burst of concurrent execs.
stress_pids=()
for i in $(seq 1 100); do
  /usr/bin/printf '%s\n' "$stress_marker-$i" >/dev/null &
  stress_pids+=("$!")
done
for child in "${stress_pids[@]}"; do
  wait "$child"
done
curl -s -o /dev/null --max-time 4 https://api.anthropic.com/ 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo "== checks =="
# Tracing may force ANSI formatting even when stderr is redirected. Strip it before checking
# structured counter fields so color codes cannot create false failures.
plain_log="${log}.plain"
sed -E $'s/\\x1B\\[[0-9;]*[[:alpha:]]//g' "$log" >"$plain_log"
grep -q "probes attached" "$log" || fail "probes did not attach"
grep -aq '"event"' "$log" || fail "no events captured"
grep -aF "$short_marker" "$log" | grep -q '"argv_truncated":false,"argv_incomplete":false' || {
  fail "short argv regressed"
}
grep -aFq "$marker-$long_arg" "$log" || fail "600-byte argv was missing or truncated"
grep -aF "$marker-$long_arg" "$log" | grep -q '"argv_truncated":false,"argv_incomplete":false' || {
  fail "long argv was marked truncated or incomplete"
}
grep -aFq "$semantic_marker-$semantic_prefix-base64 -d | sh" "$log" || {
  fail "content beyond the old 64-byte boundary was missing"
}
grep -aF "$many_marker" "$log" | grep -q '"argv_truncated":true,"argv_incomplete":false' || {
  fail "argument-count overflow was not explicitly marked truncated"
}
grep -aF "$huge_marker" "$log" | grep -q '"argv_truncated":true,"argv_incomplete":false' || {
  fail "argv-byte overflow was not explicitly marked truncated"
}
grep -aF "$proc_tail_marker" "$log" | grep -q '"argv_truncated":false,"argv_incomplete":false,"exec_confirmed":true,"argv_source":"proc_cmdline"' || {
  fail "successful exec did not recover arguments beyond the kernel cap from /proc"
}
stress_count=$(grep -aFc "$stress_marker-" "$log" || true)
[ "$stress_count" -eq 100 ] || fail "concurrent exec capture mismatch: expected 100, got $stress_count"
grep -q 'exec_reassembly_timeout=0' "$plain_log" || fail "exec reassembly timed out"
grep -q 'dropped=0 output_dropped=0' "$plain_log" || fail "collector dropped events"
echo "PASS: argv boundaries, exec confirmation, /proc supplementation, explicit truncation, concurrent reassembly, and drop counters"
rm -f "$log" "$plain_log"
