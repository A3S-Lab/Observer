#!/usr/bin/env python3
"""Real Python/OpenSSL Phase -1 fixture for the isolated plaintext pipeline.

Run the parent mode as root after building the collector. It starts a local TLS endpoint and a
separate allow-listed Python client, proves one request is parsed, engages SIGUSR2, proves a
second request is not captured, and scans ordinary Observer output for plaintext leakage.
Sensitive temporary artifacts are removed when the test exits.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import pathlib
import select
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import TextIO


CONFIRMATION = "I_UNDERSTAND_PLAINTEXT_CAPTURE"
PROVIDER_HOST = "api.openai.com"
AUTH_SECRET = "fixture-authorization-must-never-leak"


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
        response = b'{"id":"fixture","output":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def run_client(port: int) -> int:
    print(f"READY {os.getpid()}", flush=True)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    for command in sys.stdin:
        command = command.strip()
        if command == "STOP":
            return 0
        if command not in {"METADATA", "FIRST", "LARGE", "MAXIMUM", "SECOND"}:
            continue
        suffix = command.lower()
        repetitions = {
            "LARGE": 12_000,
            "MAXIMUM": 44_000,
        }.get(command, 20)
        instruction = (
            f"ANYSENTRY_PHASE1_CONTROLLED_{suffix.upper()} "
            + ("dependency-observation " * repetitions)
        )
        body = json.dumps(
            {
                "model": "fixture-openai-compatible",
                "input": [{"role": "user", "content": instruction}],
            },
            separators=(",", ":"),
        ).encode()
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            port,
            timeout=5,
            context=context,
        )
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
        response.read()
        connection.close()
        if response.status != 200:
            print(f"ERROR {response.status}", flush=True)
            return 2
        print(f"DONE {command}", flush=True)
    return 0


def read_line(stream: TextIO, timeout: float) -> str:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out waiting for fixture subprocess")
    line = stream.readline()
    if not line:
        raise RuntimeError("fixture subprocess exited before acknowledgement")
    return line.rstrip("\n")


def wait_for_text(path: pathlib.Path, needle: str, timeout: float) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if path.exists() and needle in path.read_text(errors="replace"):
            return (time.monotonic() - started) * 1000
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for collector state: {needle}")


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


def run_parent(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("the real eBPF fixture must run as root")
    collector_path = pathlib.Path(args.collector).resolve()
    if not collector_path.is_file():
        raise FileNotFoundError(f"collector not found: {collector_path}")
    libssl = pathlib.Path(args.libssl).resolve()
    if not libssl.is_file():
        raise FileNotFoundError(f"libssl not found: {libssl}")

    with tempfile.TemporaryDirectory(prefix="a3s-interaction-fixture-") as raw_directory:
        directory = pathlib.Path(raw_directory)
        certificate, private_key = generate_certificate(directory)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificate, private_key)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        client = subprocess.Popen(
            [sys.executable, str(pathlib.Path(__file__).resolve()), "--client", str(server.server_port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert client.stdout is not None
        assert client.stdin is not None
        ready = read_line(client.stdout, 5)
        if not ready.startswith("READY "):
            raise RuntimeError(f"unexpected client readiness line: {ready}")
        client_pid = int(ready.split()[1])

        metadata_output = directory / "observer-metadata.ndjson"
        metadata_log = directory / "observer-metadata.log"
        metadata_environment = os.environ.copy()
        metadata_environment.update(
            {
                "A3S_OBSERVER_JSON": "1",
                "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "metadata",
                "A3S_OBSERVER_HEARTBEAT": str(directory / "observer-metadata.alive"),
            }
        )
        with metadata_output.open("wb") as stdout_file, metadata_log.open("wb") as stderr_file:
            metadata_collector = subprocess.Popen(
                [str(collector_path)],
                env=metadata_environment,
                stdout=stdout_file,
                stderr=stderr_file,
            )
            try:
                wait_for_text(metadata_log, "probes attached", 10)
                client.stdin.write("METADATA\n")
                client.stdin.flush()
                if read_line(client.stdout, 10) != "DONE METADATA":
                    raise RuntimeError("metadata-only fixture request failed")
                time.sleep(0.2)
            finally:
                metadata_collector.send_signal(signal.SIGINT)
                try:
                    metadata_collector.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    metadata_collector.kill()
                    metadata_collector.wait(timeout=2)
        if metadata_collector.returncode != 0:
            raise RuntimeError(
                f"metadata collector exited {metadata_collector.returncode}: "
                + metadata_log.read_text(errors="replace")[-2000:]
            )
        metadata_plaintext = "ANYSENTRY_PHASE1_CONTROLLED_METADATA"
        metadata_observer_output = metadata_output.read_text(errors="replace")
        metadata_observer_log = metadata_log.read_text(errors="replace")
        if metadata_plaintext in metadata_observer_output or metadata_plaintext in metadata_observer_log:
            raise AssertionError("metadata-only mode emitted controlled plaintext")
        if '"payload_capture_enabled":false' not in metadata_observer_output:
            raise AssertionError("metadata-only heartbeat did not prove payload capture disabled")
        if "attaching isolated OpenSSL fixture probes" in metadata_observer_log:
            raise AssertionError("metadata-only mode attempted to attach payload probes")

        fixture_output = directory / "fixture-observations.jsonl"
        ordinary_output = directory / "observer.ndjson"
        collector_log = directory / "observer.log"
        environment = os.environ.copy()
        environment.update(
            {
                "A3S_OBSERVER_JSON": "1",
                "A3S_OBSERVER_INTERACTION_CAPTURE_MODE": "fixture_payload",
                "A3S_OBSERVER_ENVIRONMENT": "isolated_test",
                "A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE": CONFIRMATION,
                "A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS": str(client_pid),
                "A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT": str(fixture_output),
                "A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS": PROVIDER_HOST,
                "A3S_OBSERVER_SSL_LIBRARY": str(libssl),
                "A3S_OBSERVER_HEARTBEAT": str(directory / "observer.alive"),
            }
        )
        with ordinary_output.open("wb") as stdout_file, collector_log.open("wb") as stderr_file:
            collector = subprocess.Popen(
                [str(collector_path)],
                env=environment,
                stdout=stdout_file,
                stderr=stderr_file,
            )
            try:
                try:
                    wait_for_text(collector_log, "probes attached", 10)
                except TimeoutError as error:
                    collector.poll()
                    raise RuntimeError(
                        f"{error}; collector_exit={collector.returncode}; "
                        + collector_log.read_text(errors="replace")[-4000:]
                    ) from error
                client.stdin.write("FIRST\n")
                client.stdin.flush()
                if read_line(client.stdout, 10) != "DONE FIRST":
                    raise RuntimeError("first fixture request failed")
                wait_for_text(fixture_output, '"LlmRequestObserved"', 5)

                client.stdin.write("LARGE\n")
                client.stdin.flush()
                if read_line(client.stdout, 10) != "DONE LARGE":
                    raise RuntimeError("large multi-fragment fixture request failed")
                wait_for_text(fixture_output, "ANYSENTRY_PHASE1_CONTROLLED_LARGE", 10)

                client.stdin.write("MAXIMUM\n")
                client.stdin.flush()
                if read_line(client.stdout, 15) != "DONE MAXIMUM":
                    raise RuntimeError("maximum-size multi-fragment fixture request failed")
                wait_for_text(fixture_output, "ANYSENTRY_PHASE1_CONTROLLED_MAXIMUM", 15)

                kill_started = time.monotonic()
                collector.send_signal(signal.SIGUSR2)
                wait_for_text(collector_log, "Kill Switch engaged", 2)
                kill_switch_latency_ms = (time.monotonic() - kill_started) * 1000

                client.stdin.write("SECOND\n")
                client.stdin.flush()
                if read_line(client.stdout, 10) != "DONE SECOND":
                    raise RuntimeError("second fixture request failed")
                time.sleep(0.3)
            finally:
                collector.send_signal(signal.SIGINT)
                try:
                    collector.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    collector.kill()
                    collector.wait(timeout=2)
                client.stdin.write("STOP\n")
                client.stdin.flush()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait(timeout=2)
                server.shutdown()
                server.server_close()

        if collector.returncode != 0:
            raise RuntimeError(
                f"collector exited {collector.returncode}: "
                + collector_log.read_text(errors="replace")[-2000:]
            )
        observations = [
            json.loads(line)
            for line in fixture_output.read_text().splitlines()
            if line.strip()
        ]
        parsed = [item for item in observations if item.get("eventType") == "LlmRequestObserved"]
        if len(parsed) != 3:
            raise AssertionError(f"expected three pre-kill parsed requests, got {len(parsed)}")
        instructions = [
            item.get("userInstruction", {}).get("content", "")
            for item in parsed
        ]
        if not any("ANYSENTRY_PHASE1_CONTROLLED_FIRST" in value for value in instructions):
            raise AssertionError("the first controlled user instruction was not reconstructed")
        large_instruction = next(
            (
                value
                for value in instructions
                if "ANYSENTRY_PHASE1_CONTROLLED_LARGE" in value
            ),
            "",
        )
        large_instruction_bytes = len(large_instruction.encode())
        if large_instruction_bytes <= 128 * 1024:
            raise AssertionError(
                "large controlled instruction did not exercise multi-fragment capture"
            )
        maximum_instruction = next(
            (
                value
                for value in instructions
                if "ANYSENTRY_PHASE1_CONTROLLED_MAXIMUM" in value
            ),
            "",
        )
        maximum_instruction_bytes = len(maximum_instruction.encode())
        if not 900_000 <= maximum_instruction_bytes <= 1024 * 1024:
            raise AssertionError(
                "maximum controlled instruction did not exercise the 1 MiB boundary"
            )
        if "ANYSENTRY_PHASE1_CONTROLLED_SECOND" in fixture_output.read_text():
            raise AssertionError("payload was captured after the Kill Switch")
        mode = stat.S_IMODE(fixture_output.stat().st_mode)
        if mode != 0o600:
            raise AssertionError(f"fixture output mode is {oct(mode)}, expected 0o600")

        ordinary = ordinary_output.read_text(errors="replace")
        logs = collector_log.read_text(errors="replace")
        forbidden = [
            "ANYSENTRY_PHASE1_CONTROLLED_METADATA",
            "ANYSENTRY_PHASE1_CONTROLLED_FIRST",
            "ANYSENTRY_PHASE1_CONTROLLED_LARGE",
            "ANYSENTRY_PHASE1_CONTROLLED_MAXIMUM",
            "ANYSENTRY_PHASE1_CONTROLLED_SECOND",
            AUTH_SECRET,
        ]
        leaked = [
            marker
            for marker in forbidden
            if marker in ordinary
            or marker in logs
            or marker in metadata_observer_output
            or marker in metadata_observer_log
        ]
        if leaked:
            raise AssertionError("controlled plaintext leaked into ordinary Observer output")

        print(
            json.dumps(
                {
                    "status": "PASS",
                    "runtime": f"python-{sys.version_info.major}.{sys.version_info.minor}",
                    "openssl": ssl.OPENSSL_VERSION,
                    "schemaVersion": parsed[0].get("schemaVersion"),
                    "parsedRequests": len(parsed),
                    "multiFragmentInstructionBytes": large_instruction_bytes,
                    "maximumInstructionBytes": maximum_instruction_bytes,
                    "fixtureOutputMode": oct(mode),
                    "metadataOnlyPayloadCaptureEnabled": False,
                    "ordinaryPlaintextLeakageFindings": 0,
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
    parser.add_argument("--libssl", default="/usr/lib/x86_64-linux-gnu/libssl.so.3")
    parser.add_argument("--client", type=int, metavar="PORT")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.client is not None:
        return run_client(args.client)
    return run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
