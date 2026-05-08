"""Supply-chain heuristics for container images."""

from __future__ import annotations

from typing import Any

from .common import summarize_issues
from .docker import inspect_image


class SupplyChainScanner:
    """Perform lightweight supply-chain checks on image metadata."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def scan(self, image: str) -> dict[str, Any]:
        image_data = inspect_image(image, timeout=self.timeout)
        config = image_data.get("Config") or {}
        repo_digests = image_data.get("RepoDigests") or []
        labels = config.get("Labels") or {}
        entrypoint = config.get("Entrypoint") or []
        command = config.get("Cmd") or []
        registry = image.split("/", 1)[0] if "/" in image else "docker.io"
        trusted_registry = self._trusted_registry(registry)
        suspicious_packages = self._suspicious_packages(config.get("Env") or [], labels)
        issues = [
            self._issue(
                "SC-001",
                "Image should be pinned by digest for supply-chain integrity",
                "medium" if not repo_digests else "info",
                "fail" if not repo_digests else "pass",
                image,
                "Use immutable digests in deployment manifests when possible.",
                metadata={"repo_digests": repo_digests},
            ),
            self._issue(
                "SC-002",
                "Avoid unversioned image tags",
                "medium" if image.endswith(":latest") or ":" not in image else "info",
                "fail" if image.endswith(":latest") or ":" not in image else "pass",
                image,
                "Pin an explicit version or digest to reduce surprise updates.",
            ),
            self._issue(
                "SC-003",
                "Image should include provenance labels",
                "low" if not labels else "info",
                "fail" if not labels else "pass",
                image,
                "Add OCI labels such as source, revision, vendor, and licenses.",
                metadata={"labels": labels},
            ),
            self._issue(
                "SC-004",
                "Entrypoint and command should not look like crypto-mining or shell stagers",
                "critical" if self._looks_suspicious(entrypoint + command) else "info",
                "fail" if self._looks_suspicious(entrypoint + command) else "pass",
                image,
                "Review startup commands for downloader shells, base64 payloads, or miner-like tooling.",
                metadata={"entrypoint": entrypoint, "cmd": command},
            ),
            self._issue(
                "SC-005",
                "Image should come from a trusted registry namespace",
                "medium" if not trusted_registry else "info",
                "fail" if not trusted_registry else "pass",
                image,
                "Prefer internal registries or known publishers for production workloads.",
                metadata={"registry": registry},
            ),
            self._issue(
                "SC-006",
                "Environment and labels should not advertise risky package bootstrap behavior",
                "high" if suspicious_packages else "info",
                "fail" if suspicious_packages else "pass",
                image,
                "Review package install hooks, curl|bash bootstrap commands, and unsigned script references.",
                metadata={"signals": suspicious_packages},
            ),
        ]
        return {
            "module": "supply_chain",
            "target": image,
            "checks": issues,
            "summary": summarize_issues([issue for issue in issues if issue["status"] == "fail"]),
        }

    def _looks_suspicious(self, values: list[str]) -> bool:
        joined = " ".join(values).lower()
        indicators = ("curl ", "wget ", "base64", "xmrig", "minerd", "nc ", "bash -c", "sh -c")
        return any(indicator in joined for indicator in indicators)

    def _trusted_registry(self, registry: str) -> bool:
        trusted = {"docker.io", "ghcr.io", "quay.io", "mcr.microsoft.com", "public.ecr.aws"}
        return registry in trusted or registry.endswith(".local") or registry.endswith(".corp")

    def _suspicious_packages(self, env_vars: list[str], labels: dict[str, Any]) -> list[str]:
        joined = " ".join(env_vars + [f"{key}={value}" for key, value in labels.items()]).lower()
        indicators = ("curl|bash", "wget|sh", "pip install http", "npm install http", "apk add --allow-untrusted")
        return [indicator for indicator in indicators if indicator in joined]

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
