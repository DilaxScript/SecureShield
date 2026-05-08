"""Baseline CIS-inspired Docker checks."""

from __future__ import annotations

from typing import Any

from .common import summarize_issues
from .docker import find_running_container_for_image, inspect_container, inspect_image


class CISScanner:
    """Run practical CIS-style checks using Docker metadata."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def scan(self, image: str) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        image_data = inspect_image(image, timeout=self.timeout)
        config = image_data.get("Config") or {}

        user = config.get("User") or ""
        healthcheck = config.get("Healthcheck")
        env_vars = config.get("Env") or []
        exposed_ports = list((config.get("ExposedPorts") or {}).keys())

        issues.extend(
            [
                self._issue(
                    "CIS-IMG-001",
                    "Avoid using the latest tag",
                    "medium" if image.endswith(":latest") or ":" not in image else "info",
                    "fail" if image.endswith(":latest") or ":" not in image else "pass",
                    "image",
                    image,
                    "Pin image versions to reduce drift and unexpected updates.",
                ),
                self._issue(
                    "CIS-IMG-002",
                    "Container should not run as root",
                    "high" if not user or user in {"0", "root"} else "info",
                    "fail" if not user or user in {"0", "root"} else "pass",
                    "image",
                    image,
                    "Set a non-root USER in the Dockerfile.",
                ),
                self._issue(
                    "CIS-IMG-003",
                    "Image should define a HEALTHCHECK",
                    "low" if not healthcheck else "info",
                    "fail" if not healthcheck else "pass",
                    "image",
                    image,
                    "Add a HEALTHCHECK instruction so orchestration can detect unhealthy containers.",
                ),
                self._issue(
                    "CIS-IMG-004",
                    "Avoid baking secrets into image environment variables",
                    "high" if self._sensitive_env(env_vars) else "info",
                    "fail" if self._sensitive_env(env_vars) else "pass",
                    "image",
                    image,
                    "Move secrets to runtime secret stores or environment injection.",
                    metadata={"environment_keys": self._sensitive_env(env_vars)},
                ),
                self._issue(
                    "CIS-IMG-005",
                    "Review exposed ports",
                    "medium" if "22/tcp" in exposed_ports else "info",
                    "fail" if "22/tcp" in exposed_ports else "pass",
                    "image",
                    image,
                    "Avoid exposing SSH or unnecessary ports from the image.",
                    metadata={"ports": exposed_ports},
                ),
            ]
        )

        running_container = find_running_container_for_image(image, timeout=self.timeout)
        if running_container:
            issues.extend(self._runtime_checks(running_container))
        else:
            issues.append(
                self._issue(
                    "CIS-RT-000",
                    "Runtime-specific checks skipped",
                    "info",
                    "not_applicable",
                    "runtime",
                    image,
                    "Start a container from this image to evaluate privileged mode, seccomp, and capabilities.",
                )
            )

        return {
            "module": "cis",
            "target": image,
            "checks": issues,
            "summary": summarize_issues([issue for issue in issues if issue["status"] == "fail"]),
        }

    def _runtime_checks(self, container: str) -> list[dict[str, Any]]:
        data = inspect_container(container, timeout=self.timeout)
        host_config = data.get("HostConfig") or {}
        security_opt = host_config.get("SecurityOpt") or []
        apparmor = data.get("AppArmorProfile") or ""
        cap_add = host_config.get("CapAdd") or []

        seccomp_enabled = not any("seccomp=unconfined" in value for value in security_opt)
        return [
            self._issue(
                "CIS-RT-001",
                "Container should not run in privileged mode",
                "critical" if host_config.get("Privileged") else "info",
                "fail" if host_config.get("Privileged") else "pass",
                "runtime",
                container,
                "Disable privileged mode and use only the minimum required capabilities.",
            ),
            self._issue(
                "CIS-RT-002",
                "Container should use a read-only root filesystem",
                "medium" if not host_config.get("ReadonlyRootfs") else "info",
                "fail" if not host_config.get("ReadonlyRootfs") else "pass",
                "runtime",
                container,
                "Enable a read-only root filesystem where possible.",
            ),
            self._issue(
                "CIS-RT-003",
                "Container should keep seccomp confinement enabled",
                "high" if not seccomp_enabled else "info",
                "fail" if not seccomp_enabled else "pass",
                "runtime",
                container,
                "Avoid running with seccomp unconfined.",
            ),
            self._issue(
                "CIS-RT-004",
                "Container should use AppArmor or equivalent LSM profile",
                "medium" if not apparmor else "info",
                "fail" if not apparmor else "pass",
                "runtime",
                container,
                "Apply AppArmor or SELinux policies for container isolation.",
                metadata={"apparmor_profile": apparmor},
            ),
            self._issue(
                "CIS-RT-005",
                "Review dangerous added Linux capabilities",
                "high" if cap_add else "info",
                "fail" if cap_add else "pass",
                "runtime",
                container,
                "Drop non-essential capabilities from the container.",
                metadata={"cap_add": cap_add},
            ),
        ]

    def _sensitive_env(self, env_vars: list[str]) -> list[str]:
        return [
            value.split("=", 1)[0]
            for value in env_vars
            if any(token in value.upper() for token in ("PASSWORD", "SECRET", "TOKEN", "KEY"))
        ]

    def _issue(
        self,
        check_id: str,
        title: str,
        severity: str,
        status: str,
        category: str,
        target: str,
        remediation: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": check_id,
            "title": title,
            "severity": severity.upper(),
            "status": status,
            "category": category,
            "target": target,
            "description": title,
            "remediation": remediation,
            "metadata": metadata or {},
        }
