#!/usr/bin/env python3
"""Declared-load verifier for the isolated OpenSSL plaintext Fixture.

This is intentionally separate from production Observer startup. It targets one exact Python PID,
uses a local TLS endpoint, retains only instruction hashes in the disposable Fixture artifact, and
measures correctness, drops, resources, latency impact, leakage, and the Kill Switch.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import queue
import re
import select
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from typing import BinaryIO, TextIO


CONFIRMATION = "I_UNDERSTAND_PLAINTEXT_CAPTURE"
PROVIDER_HOST = "api.openai.com"
AUTH_SECRET = "fixture-load-authorization-must-never-leak"
LOAD_MARKER = "ANYSENTRY_PHASE1_LOAD_"


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        remaining = int(self.headers.get("Content-Length", "0"))
        while remaining:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
        response = b'{"id":"fixture-load","output":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * ratio + 0.999999) - 1))
    return ordered[index]


def instruction_size(index: int) -> int:
    slot = index % 100
    if slot == 0:
        return 128
    if slot <= 93:
        return 4_096
    if slot <= 98:
        return 65_536
    return 1_040_000


def instruction_for(label: str, index: int, size: int) -> str:
    prefix = f"{LOAD_MARKER}{label.upper()}_{index:08d} "
    if len(prefix) > size:
        raise ValueError("instruction prefix exceeds requested size")
    return prefix + ("x" * (size - len(prefix)))


def request_body(label: str, index: int) -> tuple[bytes, str, int]:
    size = instruction_size(index)
    instruction = instruction_for(label, index, size)
    digest = hashlib.sha256(instruction.encode()).hexdigest()
    body = json.dumps(
        {
            "model": "fixture-openai-compatible",
            "input": [{"role": "user", "content": instruction}],
        },
        separators=(",", ":"),
    ).encode()
    if len(body) > 1024 * 1024:
        raise ValueError(f"request body exceeded 1 MiB: {len(body)}")
    return body, digest, size


def worker(
    tasks: queue.Queue[tuple[int, bytes] | None],
    port: int,
    latencies: list[float],
    ttfts: list[float],
    latencies_by_size: dict[int, list[float]],
    ttfts_by_size: dict[int, list[float]],
    failures: list[str],
    lock: threading.Lock,
) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection: http.client.HTTPSConnection | None = None
    while True:
        item = tasks.get()
        if item is None:
            tasks.task_done()
            if connection is not None:
                connection.close()
            return
        index, body = item
        try:
            if connection is None:
                connection = http.client.HTTPSConnection(
                    "127.0.0.1",
                    port,
                    timeout=15,
                    context=context,
                )
            started = time.perf_counter()
            connection.request(
                "POST",
                "/v1/responses",
                body=body,
                headers={
                    "Host": PROVIDER_HOST,
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {AUTH_SECRET}",
                },
            )
            response = connection.getresponse()
            ttft_ms = (time.perf_counter() - started) * 1000
            response.read()
            latency_ms = (time.perf_counter() - started) * 1000
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}")
            with lock:
                ttfts.append(ttft_ms)
                latencies.append(latency_ms)
                size = instruction_size(index)
                ttfts_by_size[size].append(ttft_ms)
                latencies_by_size[size].append(latency_ms)
        except Exception as error:  # noqa: BLE001 - failure is reported as test evidence
            with lock:
                failures.append(f"{index}:{type(error).__name__}:{error}")
            if connection is not None:
                connection.close()
                connection = None
        finally:
            tasks.task_done()


def run_load(command: dict[str, object], port: int) -> dict[str, object]:
    label = str(command["label"])
    duration = float(command["durationSeconds"])
    rps = int(command["requestsPerSecond"])
    concurrency = int(command["concurrency"])
    total = max(1, round(duration * rps))
    manifest_raw = command.get("manifestPath")
    if manifest_raw:
        manifest_path = pathlib.Path(str(manifest_raw))
        manifest_fd = os.open(
            manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        manifest = os.fdopen(manifest_fd, "w", encoding="utf-8")
    else:
        manifest = None

    tasks: queue.Queue[tuple[int, bytes] | None] = queue.Queue(maxsize=concurrency * 4)
    latencies: list[float] = []
    ttfts: list[float] = []
    request_sizes = (128, 4_096, 65_536, 1_040_000)
    latencies_by_size: dict[int, list[float]] = {
        size: [] for size in request_sizes
    }
    ttfts_by_size: dict[int, list[float]] = {
        size: [] for size in request_sizes
    }
    failures: list[str] = []
    lock = threading.Lock()
    threads = [
        threading.Thread(
            target=worker,
            args=(
                tasks,
                port,
                latencies,
                ttfts,
                latencies_by_size,
                ttfts_by_size,
                failures,
                lock,
            ),
            daemon=True,
        )
        for _ in range(concurrency)
    ]
    for thread in threads:
        thread.start()

    started = time.perf_counter()
    next_progress = started + 30
    for index in range(total):
        target = started + (index / rps)
        delay = target - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        body, digest, size = request_body(label, index)
        if manifest is not None:
            manifest.write(f"{digest} {size}\n")
        tasks.put((index, body))
        now = time.perf_counter()
        if now >= next_progress:
            print(
                json.dumps(
                    {
                        "type": "progress",
                        "label": label,
                        "scheduled": index + 1,
                        "total": total,
                        "elapsedSeconds": round(now - started, 2),
                    }
                ),
                flush=True,
            )
            next_progress = now + 30
    if manifest is not None:
        manifest.close()
    tasks.join()
    for _ in threads:
        tasks.put(None)
    tasks.join()
    for thread in threads:
        thread.join(timeout=5)
    elapsed = time.perf_counter() - started
    return {
        "type": "result",
        "label": label,
        "scheduled": total,
        "completed": len(latencies),
        "failures": len(failures),
        "failureSamples": failures[:10],
        "elapsedSeconds": round(elapsed, 3),
        "achievedRequestsPerSecond": round(len(latencies) / elapsed, 3),
        "latencyMs": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies, default=0), 3),
        },
        "ttftMs": {
            "p50": round(percentile(ttfts, 0.50), 3),
            "p95": round(percentile(ttfts, 0.95), 3),
            "max": round(max(ttfts, default=0), 3),
        },
        "byInstructionBytes": {
            str(size): {
                "completed": len(latencies_by_size[size]),
                "latencyMs": {
                    "p50": round(percentile(latencies_by_size[size], 0.50), 3),
                    "p95": round(percentile(latencies_by_size[size], 0.95), 3),
                    "max": round(max(latencies_by_size[size], default=0), 3),
                },
                "ttftMs": {
                    "p50": round(percentile(ttfts_by_size[size], 0.50), 3),
                    "p95": round(percentile(ttfts_by_size[size], 0.95), 3),
                    "max": round(max(ttfts_by_size[size], default=0), 3),
                },
            }
            for size in request_sizes
        },
    }


def run_client(port: int) -> int:
    print(json.dumps({"type": "ready", "pid": os.getpid()}), flush=True)
    for line in sys.stdin:
        command = json.loads(line)
        if command.get("command") == "stop":
            return 0
        if command.get("command") != "run":
            continue
        print(json.dumps(run_load(command, port)), flush=True)
    return 0


class StreamMonitor:
    def __init__(self, stream: BinaryIO, ready_text: bytes) -> None:
        self.stream = stream
        self.ready_text = ready_text
        self.ready = threading.Event()
        self.lines: deque[str] = deque(maxlen=400)
        self.leaks: list[str] = []
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _drain(self) -> None:
        for raw in iter(self.stream.readline, b""):
            if self.ready_text in raw:
                self.ready.set()
            if LOAD_MARKER.encode() in raw:
                self.leaks.append(LOAD_MARKER)
            if AUTH_SECRET.encode() in raw:
                self.leaks.append(AUTH_SECRET)
            self.lines.append(raw.decode(errors="replace").rstrip())

    def tail(self) -> str:
        return "\n".join(self.lines)

    def join(self) -> None:
        self.thread.join(timeout=5)


def start_collector(
    collector: pathlib.Path,
    environment: dict[str, str],
) -> tuple[subprocess.Popen[bytes], StreamMonitor, StreamMonitor]:
    process = subprocess.Popen(
        [str(collector)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout = StreamMonitor(process.stdout, b"probes attached")
    stderr = StreamMonitor(process.stderr, b"probes attached")
    stdout.start()
    stderr.start()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if stdout.ready.is_set() or stderr.ready.is_set():
            return process, stdout, stderr
        if process.poll() is not None:
            break
        time.sleep(0.05)
    process.poll()
    raise RuntimeError(
        f"collector did not become ready; exit={process.returncode}\n"
        + stderr.tail()
    )


def stop_collector(
    process: subprocess.Popen[bytes],
    stdout: StreamMonitor,
    stderr: StreamMonitor,
) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    stdout.join()
    stderr.join()
    if process.returncode != 0:
        raise RuntimeError(
            f"collector exited {process.returncode}\n{stderr.tail()}"
        )


def process_cpu_seconds(pid: int) -> float:
    raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2 :].split()
    ticks = int(fields[11]) + int(fields[12])
    return ticks / os.sysconf("SC_CLK_TCK")


def process_rss_bytes(pid: int) -> int:
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


def artifact_line_count(path: pathlib.Path) -> int:
    if not path.exists():
        return 0
    with path.open("rb") as source:
        return sum(1 for _line in source)


def read_client_message(stream: TextIO, timeout: float) -> dict[str, object]:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out waiting for load client")
    line = stream.readline()
    if not line:
        raise RuntimeError("load client exited without a result")
    return json.loads(line)


def run_client_command(
    client: subprocess.Popen[str],
    command: dict[str, object],
    timeout: float,
    sample_pid: int | None = None,
) -> tuple[dict[str, object], int]:
    assert client.stdin is not None
    assert client.stdout is not None
    client.stdin.write(json.dumps(command) + "\n")
    client.stdin.flush()
    deadline = time.monotonic() + timeout
    max_rss = 0
    while time.monotonic() < deadline:
        if sample_pid is not None and pathlib.Path(f"/proc/{sample_pid}").exists():
            max_rss = max(max_rss, process_rss_bytes(sample_pid))
        ready, _, _ = select.select([client.stdout], [], [], 1)
        if not ready:
            continue
        message = json.loads(client.stdout.readline())
        if message.get("type") == "progress":
            print(json.dumps(message), flush=True)
            continue
        if message.get("type") == "result":
            return message, max_rss
    raise TimeoutError("timed out waiting for load result")


def generate_certificate(directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    certificate = directory / "fixture-cert.pem"
    private_key = directory / "fixture-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return certificate, private_key


def run_metadata_baseline(
    client: subprocess.Popen[str],
    collector: pathlib.Path,
    environment: dict[str, str],
    label: str,
    duration_seconds: int,
    requests_per_second: int,
    concurrency: int,
) -> tuple[dict[str, object], float, int, int]:
    metadata, metadata_stdout, metadata_stderr = start_collector(
        collector,
        environment,
    )
    cpu_started = process_cpu_seconds(metadata.pid)
    load_started = time.monotonic()
    try:
        result, max_rss = run_client_command(
            client,
            {
                "command": "run",
                "label": label,
                "durationSeconds": duration_seconds,
                "requestsPerSecond": requests_per_second,
                "concurrency": concurrency,
            },
            duration_seconds + 120,
            metadata.pid,
        )
        load_elapsed = time.monotonic() - load_started
        cpu_percent = (
            (process_cpu_seconds(metadata.pid) - cpu_started) / load_elapsed
        ) * 100
    finally:
        stop_collector(metadata, metadata_stdout, metadata_stderr)
    if result["failures"] != 0:
        raise AssertionError(f"{label} client failures: {result}")
    leakage_findings = len(metadata_stdout.leaks) + len(metadata_stderr.leaks)
    if leakage_findings:
        raise AssertionError(f"{label} metadata-only collector observed plaintext")
    return result, cpu_percent, max_rss, leakage_findings


def parse_final_metric(log: str, name: str) -> int:
    plain = re.sub(r"\x1b\[[0-9;]*m", "", log)
    matches = re.findall(rf"\b{name}=(\d+)", plain)
    return int(matches[-1]) if matches else -1


def validate_artifact(
    artifact: pathlib.Path,
    manifest: pathlib.Path,
) -> dict[str, object]:
    expected: dict[str, int] = {}
    for line in manifest.read_text().splitlines():
        digest, raw_size = line.split()
        expected[digest] = int(raw_size)
    observed: set[str] = set()
    loss_count = 0
    unexpected = 0
    retained_content = 0
    with artifact.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            if record.get("eventType") == "FixtureCaptureLoss":
                loss_count += 1
                continue
            if record.get("eventType") != "LlmRequestObserved":
                unexpected += 1
                continue
            instruction = record.get("userInstruction", {})
            digest = instruction.get("contentSha256")
            size = instruction.get("contentBytes")
            if "content" in instruction:
                retained_content += 1
            if digest not in expected or expected[digest] != size or digest in observed:
                unexpected += 1
                continue
            observed.add(digest)
    missing = len(expected.keys() - observed)
    return {
        "expected": len(expected),
        "observed": len(observed),
        "missing": missing,
        "unexpectedOrDuplicate": unexpected,
        "lossRecords": loss_count,
        "retainedContentRecords": retained_content,
        "completeRatio": len(observed) / len(expected) if expected else 0,
    }


def run_parent(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("the eBPF declared-load Fixture must run as root")
    collector = pathlib.Path(args.collector).resolve()
    libssl = pathlib.Path(args.libssl).resolve()
    if not collector.is_file() or not libssl.is_file():
        raise FileNotFoundError("collector or libssl is missing")

    with tempfile.TemporaryDirectory(prefix="a3s-interaction-load-") as raw_directory:
        directory = pathlib.Path(raw_directory)
        certificate, private_key = generate_certificate(directory)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        server.daemon_threads = True
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificate, private_key)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        client = subprocess.Popen(
            [
                sys.executable,
                str(pathlib.Path(__file__).resolve()),
                "--client",
                str(server.server_port),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert client.stdout is not None
        ready = read_client_message(client.stdout, 10)
        if ready.get("type") != "ready":
            raise RuntimeError(f"unexpected load-client readiness: {ready}")
        client_pid = int(ready["pid"])

        base_environment = os.environ.copy()
        base_environment.update(
            {
                "A3S_OBSERVER_JSON": "1",
                "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "metadata",
                "A3S_OBSERVER_HEARTBEAT": str(directory / "metadata-before.alive"),
            }
        )
        (
            baseline_before,
            metadata_cpu_before,
            metadata_rss_before,
            metadata_leaks_before,
        ) = run_metadata_baseline(
            client,
            collector,
            base_environment,
            "baseline-before",
            args.baseline_seconds,
            args.requests_per_second,
            args.concurrency,
        )

        artifact = directory / "fixture-load.jsonl"
        manifest = directory / "fixture-load.manifest"
        fixture_environment = os.environ.copy()
        fixture_environment.update(
            {
                "A3S_OBSERVER_JSON": "1",
                "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "fixture_payload",
                "A3S_OBSERVER_ENVIRONMENT": "isolated_test",
                "A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE": CONFIRMATION,
                "A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS": str(client_pid),
                "A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT": str(artifact),
                "A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS": PROVIDER_HOST,
                "A3S_OBSERVER_PAYLOAD_FIXTURE_RETAIN_CONTENT": "0",
                "A3S_OBSERVER_SSL_LIBRARY": str(libssl),
                "A3S_OBSERVER_HEARTBEAT": str(directory / "fixture.alive"),
            }
        )
        fixture, fixture_stdout, fixture_stderr = start_collector(
            collector,
            fixture_environment,
        )
        cpu_started = process_cpu_seconds(fixture.pid)
        load_started = time.monotonic()
        observed, fixture_max_rss = run_client_command(
            client,
            {
                "command": "run",
                "label": "observed",
                "durationSeconds": args.duration_seconds,
                "requestsPerSecond": args.requests_per_second,
                "concurrency": args.concurrency,
                "manifestPath": str(manifest),
            },
            args.duration_seconds + 180,
            fixture.pid,
        )
        load_elapsed = time.monotonic() - load_started
        fixture_cpu = (
            (process_cpu_seconds(fixture.pid) - cpu_started) / load_elapsed
        ) * 100
        drain_deadline = time.monotonic() + 10
        expected_record_count = int(observed["completed"])
        while (
            artifact_line_count(artifact) < expected_record_count
            and time.monotonic() < drain_deadline
        ):
            time.sleep(0.05)
        records_before_kill = artifact_line_count(artifact)

        kill_started = time.monotonic()
        fixture.send_signal(signal.SIGUSR2)
        deadline = time.monotonic() + 2
        while (
            "Kill Switch engaged" not in fixture_stderr.tail()
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        kill_latency_ms = (time.monotonic() - kill_started) * 1000
        post_kill, _ = run_client_command(
            client,
            {
                "command": "run",
                "label": "post-kill",
                "durationSeconds": 1,
                "requestsPerSecond": 10,
                "concurrency": min(args.concurrency, 10),
            },
            30,
            fixture.pid,
        )
        time.sleep(0.2)
        stop_collector(fixture, fixture_stdout, fixture_stderr)
        final_log = fixture_stderr.tail()

        metadata_after_environment = base_environment.copy()
        metadata_after_environment["A3S_OBSERVER_HEARTBEAT"] = str(
            directory / "metadata-after.alive"
        )
        (
            baseline_after,
            metadata_cpu_after,
            metadata_rss_after,
            metadata_leaks_after,
        ) = run_metadata_baseline(
            client,
            collector,
            metadata_after_environment,
            "baseline-after",
            args.baseline_seconds,
            args.requests_per_second,
            args.concurrency,
        )

        artifact_result = validate_artifact(artifact, manifest)
        mode = stat.S_IMODE(artifact.stat().st_mode)
        ssl_dropped = parse_final_metric(final_log, "ssl_dropped")
        capacity_dropped = parse_final_metric(
            final_log,
            "fixture_capacity_dropped",
        )
        post_kill_payload_observations = max(
            0,
            artifact_line_count(artifact) - records_before_kill,
        )
        leakage_findings = (
            metadata_leaks_before
            + metadata_leaks_after
            + len(fixture_stdout.leaks)
            + len(fixture_stderr.leaks)
        )
        baseline_p95 = min(
            float(baseline_before["latencyMs"]["p95"]),
            float(baseline_after["latencyMs"]["p95"]),
        )
        baseline_ttft_p95 = min(
            float(baseline_before["ttftMs"]["p95"]),
            float(baseline_after["ttftMs"]["p95"]),
        )
        p95_regression = (
            (float(observed["latencyMs"]["p95"]) / baseline_p95) - 1
            if baseline_p95 > 0
            else 0
        )
        ttft_regression = (
            (float(observed["ttftMs"]["p95"]) / baseline_ttft_p95) - 1
            if baseline_ttft_p95 > 0
            else 0
        )
        metadata_cpu = min(metadata_cpu_before, metadata_cpu_after)
        metadata_rss = min(metadata_rss_before, metadata_rss_after)
        cpu_increment = fixture_cpu - metadata_cpu
        rss_increment = max(0, fixture_max_rss - metadata_rss)
        checks = {
            "clientFailuresZero": observed["failures"] == 0,
            "fixtureDrainedBeforeKill": records_before_kill == expected_record_count,
            "completeRatio": artifact_result["completeRatio"] >= 0.999,
            "lossRecordsZero": artifact_result["lossRecords"] == 0,
            "unexpectedRecordsZero": artifact_result["unexpectedOrDuplicate"] == 0,
            "fixtureContentNotRetained": artifact_result["retainedContentRecords"] == 0,
            "sslRingDropsZero": ssl_dropped == 0,
            "fixtureCapacityDropsZero": capacity_dropped == 0,
            "incrementalCpuWithinFivePercent": cpu_increment <= 5,
            "incrementalRssWithin64MiB": rss_increment <= 64 * 1024 * 1024,
            "agentP95RegressionWithinTwoPercent": p95_regression <= 0.02,
            "agentTtftRegressionWithinTwoPercent": ttft_regression <= 0.02,
            "ordinaryPlaintextLeakageZero": leakage_findings == 0,
            "fixtureMode0600": mode == 0o600,
            "killSwitchWithinOneSecond": kill_latency_ms <= 1000,
            "postKillClientFailuresZero": post_kill["failures"] == 0,
            "postKillPayloadObservationsZero": post_kill_payload_observations == 0,
        }
        result = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "runtime": f"python-{sys.version_info.major}.{sys.version_info.minor}",
            "openssl": ssl.OPENSSL_VERSION,
            "durationSeconds": args.duration_seconds,
            "requestsPerSecond": args.requests_per_second,
            "concurrency": args.concurrency,
            "requestDistributionBytes": {
                "minimum": 128,
                "p50": 4096,
                "p95": 65536,
                "maximumInstruction": 1_040_000,
            },
            "baselineObserverMode": "metadata",
            "observedObserverMode": "isolated_fixture_payload_hash_only",
            "baselineMethod": "conservative-lower-p95-of-metadata-before-and-after",
            "baseline": {
                "before": baseline_before,
                "after": baseline_after,
                "comparisonP95LatencyMs": baseline_p95,
                "comparisonP95TtftMs": baseline_ttft_p95,
            },
            "observed": observed,
            "postKill": post_kill,
            "postKillPayloadObservations": post_kill_payload_observations,
            "artifact": artifact_result,
            "sslRingDrops": ssl_dropped,
            "fixtureCapacityDrops": capacity_dropped,
            "resource": {
                "metadataCpuPercent": round(metadata_cpu, 3),
                "metadataCpuBeforePercent": round(metadata_cpu_before, 3),
                "metadataCpuAfterPercent": round(metadata_cpu_after, 3),
                "fixtureCpuPercent": round(fixture_cpu, 3),
                "incrementalCpuPercent": round(cpu_increment, 3),
                "metadataRssBytes": metadata_rss,
                "metadataRssBeforeBytes": metadata_rss_before,
                "metadataRssAfterBytes": metadata_rss_after,
                "fixtureMaxRssBytes": fixture_max_rss,
                "incrementalRssBytes": rss_increment,
            },
            "agentImpact": {
                "p95LatencyRegressionRatio": round(p95_regression, 5),
                "p95TtftRegressionRatio": round(ttft_regression, 5),
            },
            "ordinaryPlaintextLeakageFindings": leakage_findings,
            "fixtureOutputMode": oct(mode),
            "killSwitchLatencyMs": round(kill_latency_ms, 2),
            "checks": checks,
        }
        print(json.dumps(result, ensure_ascii=False), flush=True)

        assert client.stdin is not None
        client.stdin.write('{"command":"stop"}\n')
        client.stdin.flush()
        client.wait(timeout=10)
        server.shutdown()
        server.server_close()
        return 0 if result["status"] == "PASS" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", default="target/release/a3s-observer-collector")
    parser.add_argument("--libssl", default="/usr/lib/x86_64-linux-gnu/libssl.so.3")
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--baseline-seconds", type=int, default=20)
    parser.add_argument("--requests-per-second", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--client", type=int, metavar="PORT")
    parser.add_argument(
        "--contract",
        action="store_true",
        help="run the frozen 900-second, 100 RPS, concurrency-32 contract",
    )
    args = parser.parse_args()
    if args.contract:
        args.duration_seconds = 900
        args.baseline_seconds = 900
        args.requests_per_second = 100
        args.concurrency = 32
    if not 1 <= args.duration_seconds <= 900:
        parser.error("duration must be 1..900 seconds")
    if not 1 <= args.baseline_seconds <= 900:
        parser.error("baseline duration must be 1..900 seconds")
    if not 1 <= args.requests_per_second <= 100:
        parser.error("requests per second must be 1..100")
    if not 1 <= args.concurrency <= 32:
        parser.error("concurrency must be 1..32")
    return args


def main() -> int:
    args = parse_args()
    if args.client is not None:
        return run_client(args.client)
    return run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
