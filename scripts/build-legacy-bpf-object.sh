#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUTPUT=${1:-$ROOT_DIR/target/linux-4.19-bpf/probes-legacy.o}
BPF_BUILDER_IMAGE=${A3S_BPF_BUILDER_IMAGE:-clickhouse/binary-builder@sha256:050ad5096036206c44ac8b015eee5bbdb3207b4250fec957b0f3abd362dfcf9f}

install -d -m 0755 "$(dirname "$OUTPUT")"
output_dir=$(cd "$(dirname "$OUTPUT")" && pwd)
output_name=$(basename "$OUTPUT")

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$ROOT_DIR:/src:ro" \
  --volume "$output_dir:/out" \
  --entrypoint clang \
  "$BPF_BUILDER_IMAGE" \
  -target bpfel \
  -O2 \
  -g0 \
  -Wall \
  -Werror \
  -fno-stack-protector \
  -fno-asynchronous-unwind-tables \
  -mllvm -enable-tail-merge=0 \
  -mllvm -disable-branch-fold \
  -mllvm -disable-block-placement \
  -c /src/a3s-observer-ebpf-legacy/src/probes.c \
  -o "/out/$output_name"

node "$SCRIPT_DIR/verify-legacy-bpf-object.mjs" "$OUTPUT"
echo "Linux 4.19 legacy BPF object built at $OUTPUT"
