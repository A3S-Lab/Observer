#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${1:-/home/chensicheng/a3s/security/release/anysentry-observer-linux-4.19-arm64-hotfix}
BUILD_DIR=${A3S_HOTFIX_BUILD_DIR:-$ROOT_DIR/target/uos20-arm64-hotfix}
OBSERVER_TARGET=aarch64-unknown-linux-gnu.2.28
OBSERVER_RUST_TARGET=aarch64-unknown-linux-gnu
MAX_GLIBC=GLIBC_2.28
TARGET_PAGE_SIZE=65536

if [[ -n "${A3S_HOTFIX_TOOL_CACHE:-}" ]]; then
  tool_cache=$A3S_HOTFIX_TOOL_CACHE
else
  tool_cache=/home/chensicheng/.config/superpowers/worktrees/AnySentry/uos20-arm64-package/.build/uos20-arm64/tools
fi
zig_bin=$tool_cache/zig-0.14.1/zig
cargo_zig_root=$tool_cache/cargo-zigbuild-0.23.0
if [[ ! -x "$zig_bin" || ! -x "$cargo_zig_root/bin/cargo-zigbuild" ]]; then
  echo "Missing cached Zig/cargo-zigbuild toolchain under $tool_cache" >&2
  exit 1
fi
if ! rustup target list --installed | grep -qx "$OBSERVER_RUST_TARGET"; then
  echo "Rust target $OBSERVER_RUST_TARGET is not installed" >&2
  exit 1
fi

install -d -m 0755 "$BUILD_DIR" "$OUTPUT_DIR"
legacy_object=$BUILD_DIR/probes-legacy.o
"$SCRIPT_DIR/build-legacy-bpf-object.sh" "$legacy_object"

export PATH="$cargo_zig_root/bin:$PATH"
export CARGO_ZIGBUILD_ZIG_PATH=$zig_bin
export CARGO_TARGET_DIR=$BUILD_DIR/cargo-target
export A3S_LEGACY_BPF_OBJECT=$legacy_object
cargo zigbuild \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  --locked \
  --release \
  --package a3s-observer-collector \
  --bin a3s-observer-collector \
  --features legacy-kernel-4-19 \
  --target "$OBSERVER_TARGET"

built_collector=$CARGO_TARGET_DIR/$OBSERVER_RUST_TARGET/release/a3s-observer-collector
collector=$OUTPUT_DIR/a3s-observer-collector
install -m 0755 "$built_collector" "$collector"

if ! LANG=C readelf -h "$collector" | grep -Eq 'Machine:[[:space:]]+AArch64'; then
  echo "Hotfix collector is not AArch64" >&2
  exit 1
fi
required_glibc=$(
  LANG=C readelf -W --version-info --dyn-syms "$collector" \
    | sed -nE 's/.*Name: GLIBC_([0-9.]+).*/\1/p' \
    | sort -V \
    | tail -n 1
)
if [[ -n "$required_glibc" ]]; then
  highest=$(printf '%s\n' "${MAX_GLIBC#GLIBC_}" "$required_glibc" | sort -V | tail -n 1)
  if [[ "$highest" != "${MAX_GLIBC#GLIBC_}" ]]; then
    echo "Collector requires GLIBC_$required_glibc, newer than $MAX_GLIBC" >&2
    exit 1
  fi
fi
load_segments=0
while read -r offset vaddr segment_align; do
  load_segments=$((load_segments + 1))
  if (( segment_align < TARGET_PAGE_SIZE )); then
    echo "PT_LOAD alignment $segment_align is smaller than $TARGET_PAGE_SIZE" >&2
    exit 1
  fi
  if (( offset % TARGET_PAGE_SIZE != vaddr % TARGET_PAGE_SIZE )); then
    echo "PT_LOAD offset/address are not congruent for 64 KiB pages" >&2
    exit 1
  fi
done < <(LANG=C readelf -lW "$collector" | awk '$1 == "LOAD" { print $2, $3, $NF }')
if (( load_segments == 0 )); then
  echo "Collector has no PT_LOAD segments" >&2
  exit 1
fi

# Target command: a3s-observer-collector --version
if command -v qemu-aarch64 >/dev/null 2>&1; then
  qemu-aarch64 "$collector" --version | grep -F 'backend=perf-kprobe-legacy'
elif ! grep -aFq 'backend=perf-kprobe-legacy' "$collector"; then
  echo "Collector does not identify the legacy backend" >&2
  exit 1
fi

observer_commit=$(git -C "$ROOT_DIR" rev-parse HEAD)
{
  echo "artifact=anysentry-observer-linux-4.19-arm64-hotfix"
  echo "observer_commit=$observer_commit"
  echo "target=$OBSERVER_TARGET"
  echo "backend=perf-kprobe-legacy"
  echo "max_glibc=$MAX_GLIBC"
  echo "target_page_size=$TARGET_PAGE_SIZE"
  echo "bpf_builder_image=${A3S_BPF_BUILDER_IMAGE:-clickhouse/binary-builder@sha256:050ad5096036206c44ac8b015eee5bbdb3207b4250fec957b0f3abd362dfcf9f}"
  echo "bpf_object_sha256=$(sha256sum "$legacy_object" | awk '{print $1}')"
  echo "rustc=$(rustc --version)"
  echo "zig=$($zig_bin version)"
  echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUTPUT_DIR/PROVENANCE"

(
  cd "$OUTPUT_DIR"
  sha256sum a3s-observer-collector PROVENANCE > SHA256SUMS
  sha256sum --check SHA256SUMS
)

echo "PASS AArch64 hotfix ABI: glibc ${required_glibc:-none} <= ${MAX_GLIBC#GLIBC_}, 64 KiB pages"
echo "AnySentry Observer hotfix staged at $OUTPUT_DIR"
