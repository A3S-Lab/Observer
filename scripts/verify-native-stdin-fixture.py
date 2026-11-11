#!/usr/bin/env python3
"""Real-kernel Phase -1 verifier for exact-PID Agent stdin observation.

The fixture captures only synthetic input sent to disposable child processes. It proves that
production-equivalent metadata mode does not read stdin payloads, that the isolated native-stdin
path reconstructs chunked fd-0 reads, and that SIGUSR2 stops further capture. The temporary 0600
plaintext artifact is deleted when the verifier exits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import TextIO


CONFIRMATION = "I_UNDERSTAND_PLAINTEXT_CAPTURE"
FIXTURE_HOST = "fixture.invalid"
METADATA_MARKER = "ANYSENTRY_NATIVE_STDIN_METADATA_20260828"
PRE_KILL_MARKER = (
    "ANYSENTRY_NATIVE_STDIN_PRE_KILL_20260828 "
    "inspect only this disposable fixture input"
)
POST_KILL_MARKER = (
    "ANYSENTRY_NATIVE_STDIN_POST_KILL_20260828 "
    "this must never appear in any observation"
)


def run_client() -> int:
    start_reading = False

    def handle_start(_signum: int, _frame: object) -> None:
        nonlocal start_reading
        start_reading = True

    signal.signal(signal.SIGUSR1, handle_start)
    print(json.dumps({"type": "ready", "pid": os.getpid()}), flush=True)
    while not start_reading:
        signal.pause()
    digest = hashlib.sha256()
    total = 0
    reads = 0
    while True:
        chunk = os.read(0, 17)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        reads += 1
    print(
        json.dumps(
            {
                "type": "done",
                "pid": os.getpid(),
                "bytes": total,
                "reads": reads,
                "sha256": digest.hexdigest(),
            }
        ),
        flush=True,
    )
    return 0


def read_json_line(stream: TextIO, timeout: float) -> dict[str, object]:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out waiting for fixture subprocess")
    line = stream.readline()
    if not line:
        raise RuntimeError("fixture subprocess exited before acknowledgement")
    return json.loads(line)


def wait_for_text(path: pathlib.Path, needle: str, timeout: float) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if path.exists() and needle in path.read_text(errors="replace"):
            return (time.monotonic() - started) * 1000
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {needle!r} in {path}")


def start_client(script: pathlib.Path) -> tuple[subprocess.Popen[str], int]:
    process = subprocess.Popen(
        [sys.executable, str(script), "--client"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    ready = read_json_line(process.stdout, 5)
    if ready.get("type") != "ready" or int(ready.get("pid", 0)) != process.pid:
        process.kill()
        raise RuntimeError(f"unexpected fixture client readiness: {ready}")
    return process, process.pid


def finish_client(process: subprocess.Popen[str], payload: str) -> dict[str, object]:
    assert process.stdin is not None
    assert process.stdout is not None
    process.send_signal(signal.SIGUSR1)
    process.stdin.write(payload)
    process.stdin.flush()
    process.stdin.close()
    done = read_json_line(process.stdout, 5)
    process.wait(timeout=5)
    if process.returncode != 0 or done.get("type") != "done":
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise RuntimeError(
            f"fixture client failed: exit={process.returncode}, done={done}, stderr={stderr}"
        )
    expected = payload.encode()
    if int(done.get("bytes", -1)) != len(expected):
        raise AssertionError(f"fixture client byte count mismatch: {done}")
    if done.get("sha256") != hashlib.sha256(expected).hexdigest():
        raise AssertionError(f"fixture client hash mismatch: {done}")
    if int(done.get("reads", 0)) < 2:
        raise AssertionError("fixture input did not exercise multi-read reassembly")
    return done


def stop_process(process: subprocess.Popen[object] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def stop_client(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.close()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_parent(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("the real eBPF native-stdin fixture must run as root")
    collector_path = pathlib.Path(args.collector).resolve()
    if not collector_path.is_file():
        raise FileNotFoundError(f"collector not found: {collector_path}")
    script = pathlib.Path(__file__).resolve()

    with tempfile.TemporaryDirectory(prefix="a3s-native-stdin-fixture-") as raw_directory:
        directory = pathlib.Path(raw_directory)
        metadata_output = directory / "metadata.ndjson"
        metadata_log = directory / "metadata.log"
        metadata_client: subprocess.Popen[str] | None = None
        metadata_collector: subprocess.Popen[bytes] | None = None
        try:
            metadata_client, _ = start_client(script)
            metadata_environment = os.environ.copy()
            metadata_environment.update(
                {
                    "A3S_OBSERVER_JSON": "1",
                    "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "metadata",
                    "A3S_OBSERVER_HEARTBEAT": str(directory / "metadata.alive"),
                }
            )
            with (
                metadata_output.open("wb") as stdout_file,
                metadata_log.open("wb") as stderr_file,
            ):
                metadata_collector = subprocess.Popen(
                    [str(collector_path)],
                    env=metadata_environment,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )
                wait_for_text(metadata_log, "probes attached", 10)
                finish_client(metadata_client, METADATA_MARKER)
                time.sleep(0.25)
                stop_process(metadata_collector)
            if metadata_collector.returncode != 0:
                raise RuntimeError(
                    f"metadata collector exited {metadata_collector.returncode}: "
                    + metadata_log.read_text(errors="replace")[-3000:]
                )
        finally:
            stop_process(metadata_collector)
            stop_client(metadata_client)

        metadata_ordinary = metadata_output.read_text(errors="replace")
        metadata_logs = metadata_log.read_text(errors="replace")
        if METADATA_MARKER in metadata_ordinary or METADATA_MARKER in metadata_logs:
            raise AssertionError("metadata-only mode emitted controlled stdin plaintext")
        if '"payload_capture_enabled":false' not in metadata_ordinary:
            raise AssertionError("metadata heartbeat did not prove payload capture disabled")
        if "native stdin payload probes attached" in metadata_logs:
            raise AssertionError("metadata-only mode attempted to attach stdin payload probes")

        pre_client: subprocess.Popen[str] | None = None
        post_client: subprocess.Popen[str] | None = None
        collector: subprocess.Popen[bytes] | None = None
        fixture_output = directory / "native-observations.jsonl"
        ordinary_output = directory / "observer.ndjson"
        collector_log = directory / "observer.log"
        kill_switch_latency_ms = 0.0
        try:
            pre_client, pre_pid = start_client(script)
            post_client, post_pid = start_client(script)
            environment = os.environ.copy()
            environment.update(
                {
                    "A3S_OBSERVER_JSON": "1",
                    "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "fixture_payload",
                    "A3S_OBSERVER_ENVIRONMENT": "isolated_test",
                    "A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE": CONFIRMATION,
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS": f"{pre_pid},{post_pid}",
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT": str(fixture_output),
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS": FIXTURE_HOST,
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_OPENSSL": "off",
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDIN": "1",
                    "A3S_OBSERVER_HEARTBEAT": str(directory / "observer.alive"),
                }
            )
            with (
                ordinary_output.open("wb") as stdout_file,
                collector_log.open("wb") as stderr_file,
            ):
                collector = subprocess.Popen(
                    [str(collector_path)],
                    env=environment,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )
                wait_for_text(collector_log, "native stdin payload probes attached", 10)
                wait_for_text(collector_log, "probes attached", 10)

                pre_done = finish_client(pre_client, PRE_KILL_MARKER)
                wait_for_text(fixture_output, PRE_KILL_MARKER, 5)

                kill_started = time.monotonic()
                collector.send_signal(signal.SIGUSR2)
                wait_for_text(collector_log, "Kill Switch engaged", 2)
                kill_switch_latency_ms = (time.monotonic() - kill_started) * 1000

                post_done = finish_client(post_client, POST_KILL_MARKER)
                time.sleep(0.25)
                stop_process(collector)
            if collector.returncode != 0:
                raise RuntimeError(
                    f"native collector exited {collector.returncode}: "
                    + collector_log.read_text(errors="replace")[-4000:]
                )
        finally:
            stop_process(collector)
            stop_client(pre_client)
            stop_client(post_client)

        observations = [
            json.loads(line)
            for line in fixture_output.read_text().splitlines()
            if line.strip()
        ]
        captured = [
            item for item in observations if item.get("eventType") == "AgentInputObserved"
        ]
        if len(captured) != 1:
            raise AssertionError(f"expected one pre-kill Agent input, got {len(captured)}")
        record = captured[0]
        instruction = record.get("userInstruction", {})
        if not isinstance(instruction, dict):
            raise AssertionError("fixture record has no UserInstructionObserved object")
        if instruction.get("content") != PRE_KILL_MARKER:
            raise AssertionError("native stdin content was not reconstructed exactly")
        if instruction.get("contentBytes") != len(PRE_KILL_MARKER.encode()):
            raise AssertionError("native stdin content byte count is incorrect")
        if instruction.get("contentSha256") != hashlib.sha256(
            PRE_KILL_MARKER.encode()
        ).hexdigest():
            raise AssertionError("native stdin content hash is incorrect")
        if POST_KILL_MARKER in fixture_output.read_text():
            raise AssertionError("stdin content was captured after the Kill Switch")
        if record.get("captureMethod") != "ebpf_stdin":
            raise AssertionError("native stdin record has the wrong capture method")
        if record.get("inputScope") != "agent_process_stdin":
            raise AssertionError("native stdin record has the wrong input scope")
        mode = stat.S_IMODE(fixture_output.stat().st_mode)
        if mode != 0o600:
            raise AssertionError(f"fixture output mode is {oct(mode)}, expected 0o600")

        ordinary = ordinary_output.read_text(errors="replace")
        logs = collector_log.read_text(errors="replace")
        leaked = [
            marker
            for marker in (METADATA_MARKER, PRE_KILL_MARKER, POST_KILL_MARKER)
            if marker in ordinary
            or marker in logs
            or marker in metadata_ordinary
            or marker in metadata_logs
        ]
        if leaked:
            raise AssertionError(f"controlled plaintext leaked into ordinary output: {leaked}")
        if "attaching isolated OpenSSL fixture probes" in logs:
            raise AssertionError("native-only fixture unexpectedly attached OpenSSL probes")

        print(
            json.dumps(
                {
                    "status": "PASS",
                    "runtime": f"python-{sys.version_info.major}.{sys.version_info.minor}",
                    "captureMethod": record.get("captureMethod"),
                    "inputScope": record.get("inputScope"),
                    "capturedInstructions": len(captured),
                    "capturedBytes": instruction.get("contentBytes"),
                    "clientReadCalls": pre_done.get("reads"),
                    "postKillClientReadCalls": post_done.get("reads"),
                    "fixtureOutputMode": oct(mode),
                    "metadataOnlyPayloadCaptureEnabled": False,
                    "ordinaryPlaintextLeakageFindings": 0,
                    "openSslFixtureAttached": False,
                    "killSwitchLatencyMs": round(kill_switch_latency_ms, 2),
                    "postKillPayloadObservations": 0,
                },
                ensure_ascii=False,
            )
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", default="target/release/a3s-observer-collector")
    parser.add_argument("--client", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.client:
        return run_client()
    return run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
