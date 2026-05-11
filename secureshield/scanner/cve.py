"""Trivy-backed CVE scanner for container images."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from secureshield import config

from .common import (
    CommandExecutionError,
    ScannerError,
    ToolNotInstalledError,
    ensure_binary,
    run_json_command,
)


class TrivyNotInstalledError(ToolNotInstalledError):
    """Raised when the Trivy binary is unavailable."""


class TrivyScanError(CommandExecutionError):
    """Raised when Trivy returns a scan failure."""


@dataclass(slots=True)
class ScanSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def as_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "unknown": self.unknown,
            "total": self.total,
        }


class CVEScanner:
    """Wrapper around Trivy image scanning."""

    def __init__(
        self,
        trivy_binary: str = "trivy",
        timeout: int = 300,
        *,
        skip_db_update: bool | None = None,
        offline_scan: bool | None = None,
    ) -> None:
        self.trivy_binary = trivy_binary
        self.timeout = max(1, min(int(timeout), 1800))
        self.skip_db_update = config.TRIVY_SKIP_DB_UPDATE if skip_db_update is None else skip_db_update
        self.offline_scan = config.TRIVY_OFFLINE_SCAN if offline_scan is None else offline_scan
        self.cache_dir = config.TRIVY_CACHE_DIR
        self.image_src = config.TRIVY_IMAGE_SRC

    def scan(self, image: str) -> dict[str, Any]:
        """Run a Trivy scan and normalize the output."""
        self._ensure_trivy_available()

        started_at = datetime.now(UTC)
        command = [
            self.trivy_binary,
            "image",
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--pkg-types",
            "os",
            "--no-progress",
            "--timeout",
            f"{self.timeout}s",
            image,
        ]
        if self.cache_dir:
            command[1:1] = ["--cache-dir", self.cache_dir]
        if self.image_src:
            command[command.index("--no-progress"):command.index("--no-progress")] = [
                "--image-src",
                self.image_src,
            ]
        if self.offline_scan:
            command.insert(-3, "--offline-scan")
        if self.skip_db_update:
            command.insert(-3, "--skip-db-update")

        try:
            raw_data = run_json_command(command, timeout=self.timeout + 15)
        except CommandExecutionError as exc:
            raise TrivyScanError(f"Trivy scan failed for '{image}': {exc}") from exc

        vulnerabilities = self._extract_vulnerabilities(raw_data)
        summary = self._build_summary(vulnerabilities)
        ended_at = datetime.now(UTC)

        return {
            "image": image,
            "scanner": "trivy",
            "status": "completed",
            "generated_at": ended_at.isoformat(),
            "started_at": started_at.isoformat(),
            "duration_seconds": round((ended_at - started_at).total_seconds(), 3),
            "summary": summary.as_dict(),
            "vulnerabilities": vulnerabilities,
        }

    def get_critical_cves(self, image: str) -> list[dict[str, Any]]:
        """Return only CRITICAL findings."""
        result = self.scan(image)
        return [
            finding
            for finding in result["vulnerabilities"]
            if finding["severity"] == "CRITICAL"
        ]

    def get_cves_by_severity(self, image: str, severity: str) -> list[dict[str, Any]]:
        """Return findings matching the requested severity."""
        normalized = severity.strip().upper()
        result = self.scan(image)
        return [
            finding
            for finding in result["vulnerabilities"]
            if finding["severity"] == normalized
        ]

    def _ensure_trivy_available(self) -> None:
        try:
            ensure_binary(self.trivy_binary)
        except ToolNotInstalledError as exc:
            raise TrivyNotInstalledError(str(exc)) from exc

    def _extract_vulnerabilities(self, raw_data: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for result in raw_data.get("Results", []):
            target = result.get("Target", "unknown")
            target_class = result.get("Class", "unknown")
            result_type = result.get("Type", "unknown")

            for vulnerability in result.get("Vulnerabilities", []) or []:
                severity = (vulnerability.get("Severity") or "UNKNOWN").upper()
                findings.append(
                    {
                        "cve_id": vulnerability.get("VulnerabilityID", "UNKNOWN"),
                        "pkg_name": vulnerability.get("PkgName", "unknown"),
                        "installed_version": vulnerability.get(
                            "InstalledVersion", "unknown"
                        ),
                        "fixed_version": vulnerability.get("FixedVersion") or "",
                        "severity": severity,
                        "title": vulnerability.get("Title") or "",
                        "description": vulnerability.get("Description") or "",
                        "primary_url": vulnerability.get("PrimaryURL") or "",
                        "cvss_score": self._extract_cvss_score(vulnerability),
                        "status": vulnerability.get("Status") or "",
                        "target": target,
                        "target_class": target_class,
                        "type": result_type,
                    }
                )

        findings.sort(
            key=lambda item: (
                self._severity_rank(item["severity"]),
                -(item.get("cvss_score") or 0.0),
                item["cve_id"],
            )
        )
        return findings

    def _extract_cvss_score(self, vulnerability: dict[str, Any]) -> float | None:
        cvss = vulnerability.get("CVSS") or {}
        scores: list[float] = []

        for vendor_data in cvss.values():
            v3_score = vendor_data.get("V3Score")
            if isinstance(v3_score, (float, int)):
                scores.append(float(v3_score))

        if scores:
            return max(scores)

        fallback = vulnerability.get("CVSSScore")
        if isinstance(fallback, (float, int)):
            return float(fallback)
        return None

    def _build_summary(self, vulnerabilities: list[dict[str, Any]]) -> ScanSummary:
        summary = ScanSummary()
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for finding in vulnerabilities:
            severity = finding["severity"]
            bucket = severity_map.get(severity, "unknown")
            setattr(summary, bucket, getattr(summary, bucket) + 1)

        return summary

    def _severity_rank(self, severity: str) -> int:
        order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "UNKNOWN": 4,
        }
        return order.get(severity, 5)


Scanner = CVEScanner
