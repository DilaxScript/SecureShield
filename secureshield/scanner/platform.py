"""Unified SecureShield scanner orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

from .cis import CISScanner
from .common import ScannerError, calculate_security_score, summarize_issues
from .cve import CVEScanner
from .runtime import RuntimeScanner
from .secrets import SecretsScanner
from .supply_chain import SupplyChainScanner


class SecureShieldScanner:
    """Coordinate all scanner modules and produce one combined result."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        self.cve = CVEScanner(timeout=timeout)
        self.cis = CISScanner(timeout=min(timeout, 60))
        self.runtime = RuntimeScanner(timeout=min(timeout, 60))
        self.supply_chain = SupplyChainScanner(timeout=min(timeout, 60))
        self.secrets = SecretsScanner()

    def scan(self, image: str, source_path: str | None = None) -> dict[str, Any]:
        return self.scan_with_progress(image, source_path=source_path)

    def scan_with_progress(
        self,
        image: str,
        source_path: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        module_results: dict[str, Any] = {}
        issues: list[dict[str, Any]] = []

        self._emit_progress(progress_callback, phase="scan_started", image=image, source_path=source_path)

        self._emit_progress(progress_callback, phase="module_started", module="cve")
        try:
            cve_result = self.cve.scan(image)
            module_results["cve"] = cve_result
            issues.extend(self._cve_issues(cve_result))
            cve_findings = len(cve_result.get("vulnerabilities", []))
        except ScannerError as exc:
            cve_result = self._module_error("cve", image, exc)
            module_results["cve"] = cve_result
            issues.append(self._error_issue("cve", image, exc))
            cve_findings = 1
        self._emit_progress(
            progress_callback,
            phase="module_completed",
            module="cve",
            findings=cve_findings,
        )

        for name, scanner in (
            ("cis", self.cis),
            ("supply_chain", self.supply_chain),
            ("runtime", self.runtime),
        ):
            self._emit_progress(progress_callback, phase="module_started", module=name)
            try:
                result = scanner.scan(image)
            except ScannerError as exc:
                result = self._module_error(name, image, exc)
                module_results[name] = result
                issues.append(self._error_issue(name, image, exc))
                self._emit_progress(
                    progress_callback,
                    phase="module_completed",
                    module=name,
                    findings=1,
                )
                continue
            module_results[name] = result
            issues.extend(
                [self._tag_issue(name, issue) for issue in result["checks"] if issue["status"] == "fail"]
            )
            self._emit_progress(
                progress_callback,
                phase="module_completed",
                module=name,
                findings=len([issue for issue in result["checks"] if issue["status"] == "fail"]),
            )

        if source_path:
            self._emit_progress(progress_callback, phase="module_started", module="secrets")
            try:
                secrets_result = self.secrets.scan(source_path)
                module_results["secrets"] = secrets_result
                issues.extend([self._tag_issue("secrets", finding) for finding in secrets_result["findings"]])
                secrets_findings = len(secrets_result.get("findings", []))
            except ScannerError as exc:
                secrets_result = self._module_error("secrets", source_path, exc)
                module_results["secrets"] = secrets_result
                issues.append(self._error_issue("secrets", source_path, exc))
                secrets_findings = 1
            self._emit_progress(
                progress_callback,
                phase="module_completed",
                module="secrets",
                findings=secrets_findings,
            )

        ended_at = datetime.now(UTC)
        result = {
            "image": image,
            "source_path": source_path,
            "status": "completed_with_errors" if any(result.get("status") == "error" for result in module_results.values()) else "completed",
            "started_at": started_at.isoformat(),
            "generated_at": ended_at.isoformat(),
            "duration_seconds": round((ended_at - started_at).total_seconds(), 3),
            "modules": module_results,
            "issues": issues,
            "summary": summarize_issues(issues),
            "security_score": calculate_security_score(issues),
        }
        self._emit_progress(
            progress_callback,
            phase="scan_completed",
            image=image,
            total_findings=result["summary"]["total"],
            security_score=result["security_score"],
        )
        return result

    def scan_cis(self, image: str) -> dict[str, Any]:
        return self.cis.scan(image)

    def scan_runtime(self, target: str) -> dict[str, Any]:
        return self.runtime.scan(target)

    def scan_supply_chain(self, image: str) -> dict[str, Any]:
        return self.supply_chain.scan(image)

    def scan_secrets(self, path: str) -> dict[str, Any]:
        return self.secrets.scan(path)

    def _cve_issues(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for finding in result["vulnerabilities"]:
            issues.append(
                {
                    "module": "cve",
                    "id": finding["cve_id"],
                    "title": finding["title"] or finding["cve_id"],
                    "severity": finding["severity"],
                    "status": "fail",
                    "target": finding["target"],
                    "description": finding["description"],
                    "remediation": (
                        f"Upgrade {finding['pkg_name']} from {finding['installed_version']} to "
                        f"{finding['fixed_version'] or 'the latest patched version'}."
                    ),
                    "metadata": finding,
                }
            )
        return issues

    def _tag_issue(self, module: str, issue: dict[str, Any]) -> dict[str, Any]:
        tagged = dict(issue)
        tagged["module"] = module
        return tagged

    def _module_error(self, module: str, target: str, exc: Exception) -> dict[str, Any]:
        return {
            "module": module,
            "target": target,
            "status": "error",
            "error": str(exc),
            "checks": [],
            "findings": [],
            "vulnerabilities": [],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "unknown": 0, "total": 1},
        }

    def _error_issue(self, module: str, target: str, exc: Exception) -> dict[str, Any]:
        return {
            "module": module,
            "id": f"{module.upper()}-ERROR",
            "title": f"{module.replace('_', ' ').title()} scan could not run",
            "severity": "HIGH",
            "status": "fail",
            "target": target,
            "description": str(exc),
            "remediation": "Check scanner prerequisites, local Docker availability, image name, and scanner configuration.",
            "metadata": {"error": str(exc)},
        }

    def _emit_progress(
        self,
        progress_callback: Callable[[dict[str, Any]], None] | None,
        **payload: Any,
    ) -> None:
        if progress_callback:
            progress_callback(payload)
