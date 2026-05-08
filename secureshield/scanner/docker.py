"""Docker CLI helpers for SecureShield scanner modules."""

from __future__ import annotations

import json
from typing import Any

from .common import CommandExecutionError, ensure_binary, run_command, run_json_command


def inspect_image(image: str, timeout: int = 30) -> dict[str, Any]:
    ensure_binary("docker")
    payload = run_json_command(["docker", "image", "inspect", image], timeout=timeout)
    if not payload:
        raise CommandExecutionError(f"Docker image '{image}' was not found.")
    return payload[0]


def inspect_container(container: str, timeout: int = 30) -> dict[str, Any]:
    ensure_binary("docker")
    payload = run_json_command(["docker", "container", "inspect", container], timeout=timeout)
    if not payload:
        raise CommandExecutionError(f"Docker container '{container}' was not found.")
    return payload[0]


def find_running_container_for_image(image: str, timeout: int = 30) -> str | None:
    ensure_binary("docker")
    completed = run_command(
        ["docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}"],
        timeout=timeout,
    )
    for line in completed.stdout.splitlines():
        container_id, image_name, container_name = (line.split("|") + ["", "", ""])[:3]
        if image_name == image or container_name == image or container_id == image:
            return container_name or container_id
    return None


def find_running_container(target: str, timeout: int = 30) -> str | None:
    ensure_binary("docker")
    completed = run_command(
        ["docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}"],
        timeout=timeout,
    )
    for line in completed.stdout.splitlines():
        container_id, image_name, container_name = (line.split("|") + ["", "", ""])[:3]
        if container_id == target or container_name == target or image_name == target:
            return container_name or container_id
    return None


def container_logs(container: str, *, tail: int = 200, timeout: int = 30) -> str:
    ensure_binary("docker")
    completed = run_command(
        ["docker", "logs", "--tail", str(tail), container],
        timeout=timeout,
    )
    return completed.stdout or completed.stderr or ""


def container_events(container: str, *, since: str = "30m", timeout: int = 30) -> list[dict[str, Any]]:
    ensure_binary("docker")
    completed = run_command(
        [
            "docker",
            "events",
            "--since",
            since,
            "--until",
            "0s",
            "--filter",
            f"container={container}",
            "--format",
            "{{json .}}",
        ],
        timeout=timeout,
    )
    events: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events
