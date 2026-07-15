#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${1:-/home/chensicheng/a3s/security/release/anysentry-bpf-container-diagnostics-uos20-arm64}
TOOL_CACHE=${A3S_HOTFIX_TOOL_CACHE:-/home/chensicheng/.config/superpowers/worktrees/AnySentry/uos20-arm64-package/.build/uos20-arm64/tools}
ZIG=$TOOL_CACHE/zig-0.14.1/zig

test -x "$ZIG" || { echo "missing Zig compiler: $ZIG" >&2; exit 1; }
install -d -m 0755 "$OUTPUT_DIR"

"$ZIG" cc \
  -target aarch64-linux-gnu.2.28 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  -Wl,-z,max-page-size=65536 \
  -Wl,-z,common-page-size=65536 \
  -s \
  "$ROOT_DIR/diagnostics/bpf-syscall-probe.c" \
  -o "$OUTPUT_DIR/a3s-bpf-syscall-probe"

install -m 0755 "$ROOT_DIR/diagnostics/run-passive-container-check.sh" "$OUTPUT_DIR/RUN_PASSIVE_CHECK.sh"
install -m 0755 "$ROOT_DIR/diagnostics/run-container-bpf-diagnostics.sh" "$OUTPUT_DIR/RUN_DIAGNOSTICS.sh"
install -m 0644 "$ROOT_DIR/diagnostics/README-container-bpf-diagnostics.md" "$OUTPUT_DIR/README.md"

commit=$(git -C "$ROOT_DIR" rev-parse HEAD)
{
  echo 'artifact=anysentry-bpf-container-diagnostics-uos20-arm64'
  echo "observer_commit=$commit"
  echo 'target=aarch64-linux-gnu.2.28'
  echo 'target_page_size=65536'
  echo 'bpf_attr_abi=linux-4.19'
  echo "zig=$($ZIG version)"
  echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUTPUT_DIR/PROVENANCE"

chmod 0755 "$OUTPUT_DIR/a3s-bpf-syscall-probe" "$OUTPUT_DIR/RUN_PASSIVE_CHECK.sh" "$OUTPUT_DIR/RUN_DIAGNOSTICS.sh"
chmod 0644 "$OUTPUT_DIR/README.md" "$OUTPUT_DIR/PROVENANCE"

(
  cd "$OUTPUT_DIR"
  sha256sum a3s-bpf-syscall-probe RUN_PASSIVE_CHECK.sh RUN_DIAGNOSTICS.sh README.md PROVENANCE > SHA256SUMS
  chmod 0644 SHA256SUMS
  sha256sum --check SHA256SUMS
)

echo "Diagnostics staged at $OUTPUT_DIR"
