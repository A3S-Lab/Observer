#!/usr/bin/env python3
"""Exact-PID eBPF stdin/stdout fixture against the real Codex executable.

The host-side parent starts Codex in a stopped wrapper, attaches the isolated native-stdio
collector from a disposable privileged container, and only then resumes Codex. The prompt and
expected response are synthetic, the plaintext artifact remains inside a temporary root-owned
0600 file, and the container-side inspector returns only hashes and metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


CONFIRMATION = "I_UNDERSTAND_PLAINTEXT_CAPTURE"
FIXTURE_HOST = "fixture.invalid"
PROMPT = (
    "ANYSENTRY_CODEX_STDIN_EBPF_FIXTURE_20260828 "
    "Reply with exactly OK and do not use tools."
)
EXPECTED_RESPONSE = "OK"


def load_private_env(path: pathlib.Path) -> dict[str, str]:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"credential file {path} must not be accessible by group or other users"
        )
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def normalized_anysentry_base(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("AnySentry base URL must be an absolute HTTP(S) URL")
    if (
        parsed.scheme == "http"
        and (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("plaintext content may use HTTP only over a loopback address")
    normalized = value.rstrip("/")
    if not normalized.endswith("/security-center"):
        normalized += "/security-center"
    return normalized


def api_json(
    url: str,
    method: str,
    body: dict[str, object] | None,
    headers: dict[str, str],
) -> dict[str, object]:
    encoded = (
        json.dumps(body, separators=(",", ":")).encode()
        if body is not None
        else None
    )
    request = urllib.request.Request(
        url,
        method=method,
        data=encoded,
        headers={"content-type": "application/json", **headers},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=30) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:2000]
        raise RuntimeError(
            f"AnySentry request failed with HTTP {error.code}: {detail}"
        ) from error
    if not isinstance(payload, dict):
        raise RuntimeError("AnySentry response is not a JSON object")
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise RuntimeError("AnySentry response data is not a JSON object")
    return data


def process_start_ticks(pid: int) -> str:
    raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    close = raw.rfind(")")
    if close < 0:
        raise RuntimeError(f"could not parse /proc/{pid}/stat")
    remaining = raw[close + 2 :].split()
    if len(remaining) <= 19:
        raise RuntimeError(f"/proc/{pid}/stat has no start-time field")
    return remaining[19]


def create_fixture_source(
    base_url: str,
    admin_env_file: pathlib.Path,
    collector_id: str,
    workspace_path: str,
    run_id: str,
) -> tuple[str, str]:
    values = load_private_env(admin_env_file)
    admin_token = (
        values.get("ANYSENTRY_ADMIN_TOKEN")
        or values.get("ANYSENTRY_MANAGEMENT_TOKEN")
        or ""
    ).strip()
    if not admin_token:
        raise ValueError("credential file has no AnySentry management token")
    created = api_json(
        f"{base_url}/sources",
        "POST",
        {
            "name": f"Codex native stdin fixture {run_id}",
            "type": "forwarder",
            "enabled": True,
            "requireToken": True,
            "collectorId": collector_id,
            "workspacePath": workspace_path,
            "owner": "observer-codex-native-stdin-fixture",
            "tags": ["interaction-content-fixture", "codex", run_id],
            "correlationClaims": {
                "enabled": True,
                "authority": "observer_runtime",
                "bindings": {
                    "collectorIds": [collector_id],
                    "workspacePaths": [workspace_path],
                },
            },
        },
        {"x-anysentry-admin-token": admin_token},
    )
    source = created.get("source")
    source_token = created.get("token")
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("sourceId"), str)
        or not isinstance(source_token, str)
    ):
        raise RuntimeError("AnySentry did not return a protected fixture source")
    return source["sourceId"], source_token


def verify_uploaded_content(
    base_url: str,
    admin_env_file: pathlib.Path,
    interaction_id: str,
    expected_content: str,
    run_id: str,
) -> None:
    values = load_private_env(admin_env_file)
    admin_token = (
        values.get("ANYSENTRY_ADMIN_TOKEN")
        or values.get("ANYSENTRY_MANAGEMENT_TOKEN")
        or ""
    ).strip()
    raw_view_token = values.get("ANYSENTRY_INTERACTION_RAW_VIEW_TOKEN", "").strip()
    if not admin_token or not raw_view_token:
        raise ValueError(
            "credential file must contain management and independent Raw View tokens"
        )
    viewed = api_json(
        f"{base_url}/interactions/{urllib.parse.quote(interaction_id, safe='')}/content",
        "GET",
        None,
        {
            "x-anysentry-admin-token": admin_token,
            "x-anysentry-raw-view-token": raw_view_token,
            "x-anysentry-raw-view-reason": urllib.parse.quote(
                f"验证真实 Codex stdin 受控采集 {run_id}",
                safe="",
            ),
            "x-anysentry-actor-id": "observer-codex-native-stdin-fixture",
        },
    )
    content = viewed.get("content")
    if content != expected_content:
        raise AssertionError(
            "authorized AnySentry read-back differs from the Codex stdio Ground Truth"
        )
    expected_bytes = expected_content.encode()
    if viewed.get("contentBytes") != len(expected_bytes):
        raise AssertionError("authorized AnySentry read-back byte count differs")
    if viewed.get("contentSha256") != hashlib.sha256(expected_bytes).hexdigest():
        raise AssertionError("authorized AnySentry read-back hash differs")


def wait_for_process_state(pid: int, expected: str, timeout: float) -> None:
    status_path = pathlib.Path(f"/proc/{pid}/status")
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if not status_path.exists():
            raise RuntimeError(f"process {pid} exited before reaching state {expected}")
        for line in status_path.read_text(errors="replace").splitlines():
            if line.startswith("State:") and expected in line:
                return
        time.sleep(0.02)
    raise TimeoutError(f"process {pid} did not reach state {expected}")


def wait_for_text(path: pathlib.Path, needle: str, timeout: float) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if path.exists() and needle in path.read_text(errors="replace"):
            return (time.monotonic() - started) * 1000
        time.sleep(0.02)
    tail = path.read_text(errors="replace")[-4000:] if path.exists() else "<missing>"
    raise TimeoutError(f"timed out waiting for {needle!r} in {path}; tail={tail}")


def wait_for_file(path: pathlib.Path, timeout: float) -> None:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for fixture artifact {path}")


def stop_codex(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.kill(process.pid, signal.SIGCONT)
    except ProcessLookupError:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def stop_container(name: str, process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    subprocess.run(
        ["docker", "stop", "--time", "5", name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def resolve_codex_native(launcher: pathlib.Path, explicit: str | None) -> pathlib.Path:
    if explicit:
        candidate = pathlib.Path(explicit).resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"Codex native executable not found: {candidate}")
        return candidate
    with launcher.open("rb") as source:
        if source.read(4) == b"\x7fELF":
            return launcher
    package_root = launcher.parent.parent
    candidates = sorted(
        candidate.resolve()
        for candidate in package_root.glob(
            "node_modules/@openai/codex-linux-*/vendor/*/bin/codex"
        )
        if candidate.is_file()
    )
    if len(candidates) != 1:
        raise RuntimeError(
            "could not resolve one Codex native executable from the launcher; "
            "pass --codex-native explicitly"
        )
    return candidates[0]


def inspect_artifact(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.inspect_artifact)
    observations = [
        json.loads(line) for line in path.read_text().splitlines() if line.strip()
    ]
    captured = [
        item for item in observations if item.get("eventType") == "AgentInputObserved"
    ]
    responses = [
        item for item in observations if item.get("eventType") == "AgentOutputObserved"
    ]
    if len(captured) != 1:
        raise AssertionError(f"expected one AgentInputObserved, got {len(captured)}")
    if len(responses) != 1:
        raise AssertionError(f"expected one AgentOutputObserved, got {len(responses)}")
    record = captured[0]
    response_record = responses[0]
    instruction = record.get("userInstruction")
    if not isinstance(instruction, dict):
        raise AssertionError("AgentInputObserved has no userInstruction object")
    content = instruction.get("content")
    if not isinstance(content, str):
        raise AssertionError("isolated Codex fixture did not retain controlled content")
    content_bytes = content.encode()
    digest = hashlib.sha256(content_bytes).hexdigest()
    if len(content_bytes) != args.expected_bytes:
        raise AssertionError("captured Codex stdin byte count differs from Ground Truth")
    if digest != args.expected_sha256:
        raise AssertionError("captured Codex stdin hash differs from Ground Truth")
    if instruction.get("contentSha256") != args.expected_sha256:
        raise AssertionError("recorded Codex stdin hash differs from Ground Truth")
    assistant_response = response_record.get("assistantResponse")
    if not isinstance(assistant_response, dict):
        raise AssertionError("AgentOutputObserved has no assistantResponse object")
    response_content = assistant_response.get("content")
    if not isinstance(response_content, str):
        raise AssertionError("isolated Codex fixture did not retain controlled response")
    response_bytes = response_content.encode()
    response_digest = hashlib.sha256(response_bytes).hexdigest()
    if len(response_bytes) != args.expected_response_bytes:
        raise AssertionError("captured Codex stdout byte count differs from Ground Truth")
    if response_digest != args.expected_response_sha256:
        raise AssertionError("captured Codex stdout hash differs from Ground Truth")
    if assistant_response.get("contentSha256") != args.expected_response_sha256:
        raise AssertionError("recorded Codex stdout hash differs from Ground Truth")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise AssertionError(f"fixture artifact mode is {oct(mode)}, expected 0o600")
    instruction_receipt: dict[str, object] | None = None
    response_receipt: dict[str, object] | None = None
    if args.anysentry_base_url:
        required = {
            "source ID": args.anysentry_source_id,
            "source token file": args.anysentry_source_token_file,
            "collector ID": args.anysentry_collector_id,
            "workspace path": args.anysentry_workspace_path,
            "agent instance ID": args.anysentry_agent_instance_id,
            "host ID": args.anysentry_host_id,
            "boot ID": args.anysentry_boot_id,
            "process start ticks": args.anysentry_process_start_ticks,
            "process executable": args.anysentry_process_exe,
            "observed wall time": args.anysentry_observed_at_ms,
            "source turn ID": args.anysentry_turn_id,
        }
        missing = [label for label, value in required.items() if value in {None, ""}]
        if missing:
            raise ValueError(
                "AnySentry upload is missing " + ", ".join(missing)
            )
        token_path = pathlib.Path(args.anysentry_source_token_file)
        token_mode = stat.S_IMODE(token_path.stat().st_mode)
        if token_mode != 0o600:
            raise PermissionError(
                f"source token file mode is {oct(token_mode)}, expected 0o600"
            )
        source_token = token_path.read_text().strip()
        if not source_token:
            raise ValueError("source token file is empty")
        source_event_fingerprint = hashlib.sha256(
            (
                f"{args.anysentry_source_id}\0{record.get('pid')}\0"
                f"{record.get('observedAtMonotonicNs')}\0{digest}"
            ).encode()
        ).hexdigest()
        turn = {
            "sourceTurnId": args.anysentry_turn_id,
            "sequence": 1,
        }
        envelope = {
            "schemaVersion": "anysentry.interaction-instruction.v1",
            "eventType": "AgentInputObserved",
            "sourceEventId": f"stdin_{source_event_fingerprint}",
            "collectorId": args.anysentry_collector_id,
            "observedAt": args.anysentry_observed_at_ms,
            "agentInstanceId": args.anysentry_agent_instance_id,
            "workspacePath": args.anysentry_workspace_path,
            "turn": turn,
            "process": {
                "hostId": args.anysentry_host_id,
                "bootId": args.anysentry_boot_id,
                "pid": record.get("pid"),
                "startTimeTicks": args.anysentry_process_start_ticks,
                "comm": record.get("comm"),
                "exe": args.anysentry_process_exe,
            },
            "input": {
                "protocol": "native_stdio",
                "inputScope": "agent_process_stdin",
                "fd": record.get("fd"),
            },
            "capture": {
                "captureMethod": "ebpf_stdin",
                "captureProfile": "isolated_fixture",
                "captureMode": "encrypted_full",
                "captureCompleteness": "complete",
                "parseStatus": "boundary_observed",
                "rawRetentionState": "encrypted",
                "presentationState": "redacted",
            },
            "userInstruction": {
                "eventType": "UserInstructionObserved",
                "messageRole": "user",
                "content": content,
                "contentBytes": len(content_bytes),
                "contentSha256": digest,
            },
        }
        instruction_receipt = api_json(
            f"{normalized_anysentry_base(args.anysentry_base_url)}/interactions/ingest-content",
            "POST",
            envelope,
            {
                "x-anysentry-source-id": args.anysentry_source_id,
                "x-anysentry-ingest-token": source_token,
            },
        )
        if (
            instruction_receipt.get("accepted") is not True
            or instruction_receipt.get("contentDisposition") != "encrypted"
            or instruction_receipt.get("contentStoreDurable") is not True
            or instruction_receipt.get("kafkaDurable") is not True
        ):
            raise AssertionError("AnySentry did not return a durable encrypted instruction receipt")
        response_source_event_fingerprint = hashlib.sha256(
            (
                f"{args.anysentry_source_id}\0{response_record.get('pid')}\0"
                f"{response_record.get('observedAtMonotonicNs')}\0{response_digest}"
            ).encode()
        ).hexdigest()
        response_observed_at = args.anysentry_observed_at_ms + max(
            1,
            int(
                (
                    int(response_record.get("observedAtMonotonicNs", 0))
                    - int(record.get("observedAtMonotonicNs", 0))
                )
                / 1_000_000
            ),
        )
        response_envelope = {
            "schemaVersion": "anysentry.interaction-response.v1",
            "eventType": "AgentOutputObserved",
            "sourceEventId": f"stdout_{response_source_event_fingerprint}",
            "collectorId": args.anysentry_collector_id,
            "observedAt": response_observed_at,
            "agentInstanceId": args.anysentry_agent_instance_id,
            "workspacePath": args.anysentry_workspace_path,
            "turn": turn,
            "process": {
                "hostId": args.anysentry_host_id,
                "bootId": args.anysentry_boot_id,
                "pid": response_record.get("pid"),
                "startTimeTicks": args.anysentry_process_start_ticks,
                "comm": response_record.get("comm"),
                "exe": args.anysentry_process_exe,
            },
            "output": {
                "protocol": "native_stdio",
                "outputScope": "agent_process_stdout",
                "fd": response_record.get("fd"),
            },
            "capture": {
                "captureMethod": "ebpf_stdout",
                "captureProfile": "isolated_fixture",
                "captureMode": "encrypted_full",
                "captureCompleteness": "complete",
                "parseStatus": "boundary_observed",
                "rawRetentionState": "encrypted",
                "presentationState": "redacted",
            },
            "assistantResponse": {
                "eventType": "AssistantResponseObserved",
                "messageRole": "assistant",
                "content": response_content,
                "contentBytes": len(response_bytes),
                "contentSha256": response_digest,
            },
        }
        response_receipt = api_json(
            f"{normalized_anysentry_base(args.anysentry_base_url)}/interactions/ingest-content",
            "POST",
            response_envelope,
            {
                "x-anysentry-source-id": args.anysentry_source_id,
                "x-anysentry-ingest-token": source_token,
            },
        )
        if (
            response_receipt.get("accepted") is not True
            or response_receipt.get("contentDisposition") != "encrypted"
            or response_receipt.get("contentStoreDurable") is not True
            or response_receipt.get("kafkaDurable") is not True
        ):
            raise AssertionError("AnySentry did not return a durable encrypted response receipt")
        if instruction_receipt.get("conversationId") != response_receipt.get("conversationId"):
            raise AssertionError("instruction and response were projected into different conversations")
    print(
        json.dumps(
            {
                "status": "PASS",
                "capturedInstructions": len(captured),
                "capturedResponses": len(responses),
                "capturedBytes": len(content_bytes),
                "capturedSha256": digest,
                "capturedResponseBytes": len(response_bytes),
                "capturedResponseSha256": response_digest,
                "captureMethod": record.get("captureMethod"),
                "inputScope": record.get("inputScope"),
                "comm": record.get("comm"),
                "fixtureOutputMode": oct(mode),
                "uploaded": instruction_receipt is not None and response_receipt is not None,
                "interactionId": (
                    instruction_receipt.get("interactionId")
                    if instruction_receipt
                    else None
                ),
                "responseInteractionId": (
                    response_receipt.get("interactionId")
                    if response_receipt
                    else None
                ),
                "conversationId": (
                    instruction_receipt.get("conversationId")
                    if instruction_receipt
                    else None
                ),
                "contentRef": (
                    instruction_receipt.get("contentRef")
                    if instruction_receipt
                    else None
                ),
                "responseContentRef": (
                    response_receipt.get("contentRef")
                    if response_receipt
                    else None
                ),
            }
        )
    )
    return 0


def run_parent(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        raise PermissionError(
            "run the parent as the normal Codex account; Docker provides only the collector privilege"
        )
    collector = pathlib.Path(args.collector).resolve()
    if not collector.is_file():
        raise FileNotFoundError(f"collector not found: {collector}")
    codex_launcher = pathlib.Path(args.codex or shutil.which("codex") or "").resolve()
    if not codex_launcher.is_file():
        raise FileNotFoundError("codex executable was not found")
    codex_native = resolve_codex_native(codex_launcher, args.codex_native)
    repository = pathlib.Path(__file__).resolve().parent.parent
    expected_bytes = PROMPT.encode()
    expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()
    expected_response_bytes = EXPECTED_RESPONSE.encode()
    expected_response_sha256 = hashlib.sha256(expected_response_bytes).hexdigest()
    container_name = f"a3s-codex-stdin-fixture-{uuid.uuid4().hex[:12]}"
    run_id = f"codex-stdin-{uuid.uuid4().hex[:12]}"
    anysentry_base_url = (
        normalized_anysentry_base(args.anysentry_base_url)
        if args.anysentry_base_url
        else None
    )
    if bool(anysentry_base_url) != bool(args.anysentry_admin_env_file):
        raise ValueError(
            "--anysentry-base-url and --anysentry-admin-env-file must be provided together"
        )
    collector_id = args.anysentry_collector_id or f"{run_id}-collector"
    workspace_path = args.anysentry_workspace_path or "/tmp"

    codex_process: subprocess.Popen[bytes] | None = None
    collector_process: subprocess.Popen[bytes] | None = None
    with (
        tempfile.TemporaryDirectory(prefix="a3s-codex-stdin-fixture-") as raw_directory,
        tempfile.TemporaryDirectory(prefix="a3s-codex-ephemeral-home-") as raw_codex_home,
    ):
        directory = pathlib.Path(raw_directory)
        codex_home = pathlib.Path(raw_codex_home)
        codex_home.chmod(0o700)
        source_codex_home = pathlib.Path(
            os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".codex"))
        )
        source_auth = source_codex_home / "auth.json"
        if not source_auth.is_file():
            raise FileNotFoundError(
                f"Codex authentication file was not found at {source_auth}"
            )
        ephemeral_auth = codex_home / "auth.json"
        shutil.copyfile(source_auth, ephemeral_auth)
        ephemeral_auth.chmod(0o600)
        codex_environment = os.environ.copy()
        codex_environment["CODEX_HOME"] = str(codex_home)
        fixture_output = directory / "codex-observations.jsonl"
        ordinary_output = directory / "observer.ndjson"
        collector_log = directory / "observer.log"
        codex_stdout = b""
        codex_stderr = b""
        try:
            codex_command = [
                "/bin/bash",
                "-c",
                'kill -STOP $$; exec "$@"',
                "a3s-codex-fixture-wrapper",
                str(codex_native),
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--sandbox",
                "workspace-write",
                "--color",
                "never",
                "-C",
                "/tmp",
                "-",
            ]
            codex_process = subprocess.Popen(
                codex_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=codex_environment,
            )
            wait_for_process_state(codex_process.pid, "T (stopped)", 5)
            codex_start_ticks = process_start_ticks(codex_process.pid)
            observed_at_ms = int(time.time() * 1000)
            agent_instance_id = (
                args.anysentry_agent_instance_id
                or f"codex-native-{codex_process.pid}-{codex_start_ticks}"
            )
            host_id = os.uname().nodename
            boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            source_id: str | None = None
            if anysentry_base_url:
                source_id, source_token = create_fixture_source(
                    anysentry_base_url,
                    pathlib.Path(args.anysentry_admin_env_file).resolve(),
                    collector_id,
                    workspace_path,
                    run_id,
                )
                source_token_file = directory / "anysentry-source-token"
                source_token_file.write_text(source_token)
                source_token_file.chmod(0o600)

            docker_command = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--privileged",
                "--pid=host",
                "--network=host",
                "-v",
                "/sys:/sys",
                "-v",
                f"{repository}:/work:ro",
                "-v",
                f"{directory}:/fixture",
                "-w",
                "/work",
                "-e",
                "A3S_OBSERVER_JSON=1",
                "-e",
                "A3S_OBSERVER_INTERACTION_CAPTURE_MODE=fixture_payload",
                "-e",
                "A3S_OBSERVER_ENVIRONMENT=isolated_test",
                "-e",
                f"A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE={CONFIRMATION}",
                "-e",
                f"A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS={codex_process.pid}",
                "-e",
                "A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT=/fixture/codex-observations.jsonl",
                "-e",
                f"A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS={FIXTURE_HOST}",
                "-e",
                "A3S_OBSERVER_PAYLOAD_FIXTURE_OPENSSL=off",
                "-e",
                "A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDIN=1",
                "-e",
                "A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDOUT=1",
                "-e",
                "A3S_OBSERVER_HEARTBEAT=/fixture/observer.alive",
                "python:3.12-slim",
                "/work/target/release/a3s-observer-collector",
            ]
            with (
                ordinary_output.open("wb") as stdout_file,
                collector_log.open("wb") as stderr_file,
            ):
                collector_process = subprocess.Popen(
                    docker_command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )
                wait_for_text(collector_log, "native stdin payload probes attached", 15)
                wait_for_text(collector_log, "native stdout payload probes attached", 15)
                wait_for_text(collector_log, "probes attached", 15)

                assert codex_process.stdin is not None
                codex_process.stdin.write(expected_bytes)
                codex_process.stdin.flush()
                codex_process.stdin.close()
                codex_process.stdin = None
                os.kill(codex_process.pid, signal.SIGCONT)
                codex_stdout, codex_stderr = codex_process.communicate(
                    timeout=args.codex_timeout_seconds
                )
                if codex_process.returncode != 0:
                    raise RuntimeError(
                        f"Codex fixture exited {codex_process.returncode}: "
                        + codex_stderr.decode(errors="replace")[-4000:]
                    )
                if "OK" not in codex_stdout.decode(errors="replace"):
                    raise AssertionError("Codex fixture did not return the expected OK response")
                try:
                    wait_for_file(fixture_output, 10)
                except TimeoutError as error:
                    raise AssertionError(
                        f"{error}; collector log tail="
                        + collector_log.read_text(errors="replace")[-6000:]
                    ) from error

                inspect_command = [
                    "docker",
                    "exec",
                    container_name,
                    "python3",
                    "/work/scripts/verify-codex-native-stdin-fixture.py",
                    "--inspect-artifact",
                    "/fixture/codex-observations.jsonl",
                    "--expected-sha256",
                    expected_sha256,
                    "--expected-bytes",
                    str(len(expected_bytes)),
                    "--expected-response-sha256",
                    expected_response_sha256,
                    "--expected-response-bytes",
                    str(len(expected_response_bytes)),
                ]
                if anysentry_base_url and source_id:
                    inspect_command.extend(
                        [
                            "--anysentry-base-url",
                            anysentry_base_url,
                            "--anysentry-source-id",
                            source_id,
                            "--anysentry-source-token-file",
                            "/fixture/anysentry-source-token",
                            "--anysentry-collector-id",
                            collector_id,
                            "--anysentry-workspace-path",
                            workspace_path,
                            "--anysentry-agent-instance-id",
                            agent_instance_id,
                            "--anysentry-host-id",
                            host_id,
                            "--anysentry-boot-id",
                            boot_id,
                            "--anysentry-process-start-ticks",
                            codex_start_ticks,
                            "--anysentry-process-exe",
                            str(codex_native),
                            "--anysentry-observed-at-ms",
                            str(observed_at_ms),
                            "--anysentry-turn-id",
                            run_id,
                        ]
                    )
                inspected = subprocess.run(
                    inspect_command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                inspection = json.loads(inspected.stdout)
                raw_content_verified = False
                if anysentry_base_url:
                    interaction_id = inspection.get("interactionId")
                    if not isinstance(interaction_id, str):
                        raise AssertionError(
                            "AnySentry upload did not return an interaction ID"
                        )
                    verify_uploaded_content(
                        anysentry_base_url,
                        pathlib.Path(args.anysentry_admin_env_file).resolve(),
                        interaction_id,
                        PROMPT,
                        run_id,
                    )
                    response_interaction_id = inspection.get("responseInteractionId")
                    if not isinstance(response_interaction_id, str):
                        raise AssertionError(
                            "AnySentry upload did not return a response interaction ID"
                        )
                    verify_uploaded_content(
                        anysentry_base_url,
                        pathlib.Path(args.anysentry_admin_env_file).resolve(),
                        response_interaction_id,
                        EXPECTED_RESPONSE,
                        run_id,
                    )
                    raw_content_verified = True
                stop_container(container_name, collector_process)
        finally:
            stop_container(container_name, collector_process)
            stop_codex(codex_process)

        if collector_process is None or collector_process.returncode != 0:
            raise RuntimeError(
                "Codex stdin collector did not exit cleanly: "
                + collector_log.read_text(errors="replace")[-4000:]
            )
        ordinary = ordinary_output.read_text(errors="replace")
        logs = collector_log.read_text(errors="replace")
        if PROMPT in ordinary or PROMPT in logs:
            raise AssertionError("controlled Codex prompt leaked into ordinary Observer output")
        if "attaching isolated OpenSSL fixture probes" in logs:
            raise AssertionError("Codex stdin fixture unexpectedly attached OpenSSL probes")

        version = subprocess.run(
            [str(codex_launcher), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "runtime": version,
                    "runtimePath": str(codex_native),
                    "runtimeMode": "codex exec -",
                    "captureMethod": inspection.get("captureMethod"),
                    "inputScope": inspection.get("inputScope"),
                    "comm": inspection.get("comm"),
                    "capturedInstructions": inspection.get("capturedInstructions"),
                    "capturedResponses": inspection.get("capturedResponses"),
                    "capturedBytes": inspection.get("capturedBytes"),
                    "fixtureOutputMode": inspection.get("fixtureOutputMode"),
                    "codexExitCode": codex_process.returncode,
                    "codexResponseMatched": True,
                    "ordinaryPlaintextLeakageFindings": 0,
                    "openSslFixtureAttached": False,
                    "productionCaptureModeChanged": False,
                    "uploadedToAnySentry": inspection.get("uploaded"),
                    "interactionId": inspection.get("interactionId"),
                    "responseInteractionId": inspection.get("responseInteractionId"),
                    "conversationId": inspection.get("conversationId"),
                    "contentRef": inspection.get("contentRef"),
                    "responseContentRef": inspection.get("responseContentRef"),
                    "authorizedRawContentVerified": raw_content_verified,
                },
                ensure_ascii=False,
            )
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", default="target/release/a3s-observer-collector")
    parser.add_argument("--codex")
    parser.add_argument("--codex-native")
    parser.add_argument("--codex-timeout-seconds", type=float, default=180)
    parser.add_argument("--inspect-artifact")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-bytes", type=int)
    parser.add_argument("--expected-response-sha256")
    parser.add_argument("--expected-response-bytes", type=int)
    parser.add_argument("--anysentry-base-url")
    parser.add_argument("--anysentry-admin-env-file")
    parser.add_argument("--anysentry-source-id")
    parser.add_argument("--anysentry-source-token-file")
    parser.add_argument("--anysentry-collector-id")
    parser.add_argument("--anysentry-workspace-path")
    parser.add_argument("--anysentry-agent-instance-id")
    parser.add_argument("--anysentry-host-id")
    parser.add_argument("--anysentry-boot-id")
    parser.add_argument("--anysentry-process-start-ticks")
    parser.add_argument("--anysentry-process-exe")
    parser.add_argument("--anysentry-observed-at-ms", type=int)
    parser.add_argument("--anysentry-turn-id")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inspect_artifact:
        if (
            not args.expected_sha256
            or args.expected_bytes is None
            or not args.expected_response_sha256
            or args.expected_response_bytes is None
        ):
            raise ValueError(
                "artifact inspection requires expected stdin/stdout SHA-256 and byte counts"
            )
        return inspect_artifact(args)
    return run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
