"""Runtime security posture inspection for Docker containers."""

from __future__ import annotations

from typing import Any

from .common import CommandExecutionError, summarize_issues
from .docker import container_events, container_logs, find_running_container, inspect_container


class RuntimeScanner:
    """Inspect runtime security posture for a running container."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def scan(self, target: str) -> dict[str, Any]:
        container = self._resolve_container(target)
        if not container:
            return {
                "module": "runtime",
                "target": target,
                "checks": [
                    self._issue(
                        "RUN-000",
                        "Runtime checks skipped",
                        "info",
                        "not_applicable",
                        target,
                        "No running container matched this target. Start the container before runtime analysis.",
                    )
                ],
                "summary": summarize_issues([]),
            }

        data = inspect_container(container, timeout=self.timeout)
        host_config = data.get("HostConfig") or {}
        mounts = data.get("Mounts") or []
        pid_mode = host_config.get("PidMode") or ""
        ipc_mode = host_config.get("IpcMode") or ""
        network_mode = host_config.get("NetworkMode") or "default"
        recent_events = self._safe_container_events(container)
        recent_logs = self._safe_container_logs(container)
        issues = [
            self._issue(
                "RUN-001",
                "Privileged mode is disabled",
                "critical" if host_config.get("Privileged") else "info",
                "fail" if host_config.get("Privileged") else "pass",
                container,
                "Disable --privileged and grant only explicit capabilities.",
            ),
            self._issue(
                "RUN-002",
                "Read-only root filesystem is enabled",
                "medium" if not host_config.get("ReadonlyRootfs") else "info",
                "fail" if not host_config.get("ReadonlyRootfs") else "pass",
                container,
                "Use --read-only for workloads that do not need to write to the root filesystem.",
            ),
            self._issue(
                "RUN-003",
                "Host namespace sharing is avoided",
                "high" if pid_mode == "host" or ipc_mode == "host" else "info",
                "fail" if pid_mode == "host" or ipc_mode == "host" else "pass",
                container,
                "Avoid sharing host PID or IPC namespaces with the container.",
                metadata={"pid_mode": pid_mode, "ipc_mode": ipc_mode},
            ),
            self._issue(
                "RUN-004",
                "Host networking is avoided",
                "high" if network_mode == "host" else "info",
                "fail" if network_mode == "host" else "pass",
                container,
                "Prefer bridge or user-defined networks instead of host network mode.",
                metadata={"network_mode": network_mode},
            ),
            self._issue(
                "RUN-005",
                "Sensitive host mounts are minimized",
                "high" if self._has_sensitive_mount(mounts) else "info",
                "fail" if self._has_sensitive_mount(mounts) else "pass",
                container,
                "Avoid mounting /var/run/docker.sock, /proc, /sys, or host root paths into containers.",
                metadata={"mounts": mounts},
            ),
            self._issue(
                "RUN-006",
                "Container restart churn is low",
                "medium" if self._has_restart_churn(recent_events) else "info",
                "fail" if self._has_restart_churn(recent_events) else "pass",
                container,
                "Review crash loops, restart policies, and suspicious repeated restarts.",
                metadata={"recent_events": recent_events[-10:]},
            ),
            self._issue(
                "RUN-007",
                "Runtime logs do not indicate suspicious shell/download activity",
                "high" if self._logs_look_suspicious(recent_logs) else "info",
                "fail" if self._logs_look_suspicious(recent_logs) else "pass",
                container,
                "Investigate shells, downloaders, or encoded payload markers seen in container logs.",
            ),
        ]
        return {
            "module": "runtime",
            "target": container,
            "checks": issues,
            "summary": summarize_issues([issue for issue in issues if issue["status"] == "fail"]),
        }

    def _resolve_container(self, target: str) -> str | None:
        return find_running_container(target, timeout=self.timeout)

    def _safe_container_events(self, container: str) -> list[dict[str, Any]]:
        try:
            return container_events(container, timeout=self.timeout)
        except CommandExecutionError:
            return []

    def _safe_container_logs(self, container: str) -> str:
        try:
            return container_logs(container, timeout=self.timeout)
        except CommandExecutionError:
            return ""

    def _has_sensitive_mount(self, mounts: list[dict[str, Any]]) -> bool:
        risky_sources = ("/var/run/docker.sock", "/proc", "/sys")
        for mount in mounts:
            source = mount.get("Source") or ""
            if any(source == value or source.startswith(f"{value}/") for value in risky_sources):
                return True
        return False

    def _has_restart_churn(self, events: list[dict[str, Any]]) -> bool:
        restart_like = {"die", "restart", "kill", "oom"}
        return len([event for event in events if str(event.get("Action") or "").lower() in restart_like]) >= 3

    def _logs_look_suspicious(self, logs: str) -> bool:
        lowered = logs.lower()
        indicators = (
            "bash -c",
            "sh -c",
            "curl http",
            "wget http",
            "base64 -d",
            "permission denied",
            "reverse shell",
            "nc -e",
            "/bin/sh",
        )
        return any(indicator in lowered for indicator in indicators)

    def _issue(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        target: str,
        remediation: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": check_id,
            "title": title,
            "severity": severity.upper(),
            "status": status,
            "target": target,
            "description": title,
            "remediation": remediation,
            "metadata": metadata or {},
        }
