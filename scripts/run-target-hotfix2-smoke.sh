#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COLLECTOR="$SCRIPT_DIR/a3s-observer-collector"
RUN_DIR=$(mktemp -d /tmp/anysentry-observer-hotfix2.XXXXXX)
HEARTBEAT="$RUN_DIR/collector.alive"
STDOUT_LOG="$RUN_DIR/collector.stdout"
STDERR_LOG="$RUN_DIR/collector.stderr"
collector_pid=""
observer_was_active=0

cleanup() {
  if [[ -n "${collector_pid:-}" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    kill -TERM "$collector_pid" 2>/dev/null || true
    wait "$collector_pid" 2>/dev/null || true
  fi
  if (( observer_was_active )); then
    systemctl start anysentry-observer.service >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

fail() {
  echo "RESULT=FAIL: $*" >&2
  echo "logs=$RUN_DIR" >&2
  exit 1
}

if (( EUID != 0 )); then
  fail "please run this script as root"
fi
if [[ ! -x "$COLLECTOR" ]]; then
  fail "missing executable next to this script: $COLLECTOR"
fi

echo "AnySentry Observer Linux 4.19 hotfix2 smoke test"
echo "collector=$COLLECTOR"
echo "logs=$RUN_DIR"

if [[ -f "$SCRIPT_DIR/SHA256SUMS" ]]; then
  echo "===== checksum ====="
  (cd "$SCRIPT_DIR" && sha256sum --check SHA256SUMS) || fail "checksum verification failed"
fi

echo "===== collector version ====="
"$COLLECTOR" --version || fail "collector cannot execute on this host"

if systemctl is-active --quiet anysentry-observer.service 2>/dev/null; then
  observer_was_active=1
fi
systemctl stop anysentry-observer.service 2>/dev/null || true

A3S_OBSERVER_JSON=1 \
A3S_OBSERVER_FILES=1 \
A3S_OBSERVER_HEARTBEAT="$HEARTBEAT" \
  "$COLLECTOR" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
collector_pid=$!

ready=0
for _ in $(seq 1 15); do
  if [[ -f "$HEARTBEAT" ]]; then
    ready=1
    break
  fi
  kill -0 "$collector_pid" 2>/dev/null || break
  sleep 1
done

running=0
if kill -0 "$collector_pid" 2>/dev/null; then
  running=1
fi

/bin/sh -c 'echo anysentry-hotfix2-smoke >/dev/null'
/usr/bin/env >/dev/null
/bin/true
sleep 3

if kill -0 "$collector_pid" 2>/dev/null; then
  kill -TERM "$collector_pid" 2>/dev/null || true
  wait "$collector_pid"
  collector_rc=$?
else
  wait "$collector_pid"
  collector_rc=$?
fi
collector_pid=""

echo "heartbeat=$HEARTBEAT"
echo "heartbeat_ready=$ready"
echo "collector_running_before_stop=$running"
echo "collector_exit_code=$collector_rc"
echo "===== collector stderr ====="
sed -n '1,240p' "$STDERR_LOG"
echo "===== collector stdout ====="
sed -n '1,100p' "$STDOUT_LOG"

failure=0
if (( ready != 1 )); then
  echo "CHECK=FAIL heartbeat was not created" >&2
  failure=1
fi
if (( running != 1 )); then
  echo "CHECK=FAIL collector exited before the smoke events" >&2
  failure=1
fi
if (( collector_rc != 0 )); then
  echo "CHECK=FAIL collector exit code is $collector_rc" >&2
  failure=1
fi
if ! grep -Fq 'legacy Observer probes attached' "$STDERR_LOG"; then
  echo "CHECK=FAIL successful legacy probe attachment was not reported" >&2
  failure=1
fi
if grep -Eq 'BPF_BTF_LOAD|BPF_PROG_LOAD|legacy probe load failed|no effective legacy probes attached' "$STDERR_LOG"; then
  echo "CHECK=FAIL a BPF load failure was reported" >&2
  failure=1
fi
if [[ ! -s "$STDOUT_LOG" ]]; then
  echo "CHECK=FAIL collector emitted no JSON events" >&2
  failure=1
fi

if (( failure != 0 )); then
  fail "hotfix2 is not compatible with this target kernel"
fi

echo "RESULT=PASS: Linux 4.19 legacy Observer loaded probes and emitted events"
echo "logs=$RUN_DIR"
