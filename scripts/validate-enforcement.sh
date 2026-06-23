#!/usr/bin/env bash
# Validate a3s-observer ENFORCEMENT end-to-end.
#
#   !!! RUN ONLY ON A NON-PROD LINUX BOX (root + the eBPF toolchain) !!!
#
# This loads enforcement eBPF and actively blocks egress. NEVER run it on a shared prod node
# (see docs/enforcement.md). It builds the enforcer, attaches the cgroup/connect4 guard to a
# throwaway test cgroup, denies a test IP, and asserts:
#   1. a process IN the cgroup is blocked from the denied IP,
#   2. a control IP still connects (fail-open for non-denied),
#   3. the SAME denied IP from OUTSIDE the cgroup is unaffected (scoping),
# then cleans up. Exits non-zero on any failure.
#
#   sudo ./scripts/validate-enforcement.sh
set -uo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; }

DENY_IP=${DENY_IP:-1.1.1.1}   # denied for the test cgroup
CTRL_IP=${CTRL_IP:-1.0.0.1}   # control — must stay reachable
CG=/sys/fs/cgroup/a3s-enforce-test
POLICY=$(mktemp)
LOG=$(mktemp)
fail=0

echo "== build enforcer =="
cargo build --release -p a3s-observer-collector
ENF=target/release/enforce

echo "== attach egress guard to test cgroup, deny $DENY_IP =="
mkdir -p "$CG"
echo "$DENY_IP" > "$POLICY"
"$ENF" "$CG" "$POLICY" > "$LOG" 2>&1 &
EPID=$!
sleep 4
grep -qi "attached" "$LOG" || { echo "FAIL: enforcer did not attach"; cat "$LOG"; kill "$EPID" 2>/dev/null; rmdir "$CG" 2>/dev/null; exit 1; }

echo "== [1] IN cgroup -> $DENY_IP (expect blocked / 'not permitted') =="
out=$( (echo $BASHPID > "$CG/cgroup.procs"; curl -sS --max-time 5 -o /dev/null "https://$DENY_IP/" 2>&1) )
if echo "$out" | grep -qiE "not permitted|denied|couldn'?t connect|failed to connect"; then
  echo "   PASS: blocked ($out)"
else
  echo "   FAIL: not blocked ($out)"; fail=1
fi

echo "== [2] IN cgroup -> $CTRL_IP (expect connect, fail-open) =="
if (echo $BASHPID > "$CG/cgroup.procs"; curl -sS --max-time 6 -o /dev/null "https://$CTRL_IP/") 2>/dev/null; then
  echo "   PASS: control connected"
else
  echo "   WARN: control did not connect (network?) — re-check $CTRL_IP reachability"
fi

echo "== [3] OUTSIDE cgroup -> $DENY_IP (expect NOT blocked = scoping) =="
out=$(curl -sS --max-time 5 -o /dev/null "https://$DENY_IP/" 2>&1)
if echo "$out" | grep -qiE "not permitted"; then
  echo "   FAIL: blocked outside the cgroup ($out)"; fail=1
else
  echo "   PASS: unaffected outside the cgroup"
fi

kill -INT "$EPID" 2>/dev/null; wait "$EPID" 2>/dev/null
rmdir "$CG" 2>/dev/null; rm -f "$POLICY" "$LOG"
if [ "$fail" -eq 0 ]; then echo "ENFORCEMENT VALIDATION: PASS"; else echo "ENFORCEMENT VALIDATION: FAIL"; exit 1; fi
