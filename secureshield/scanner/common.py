"""Shared helpers and result models for SecureShield scanners."""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ScannerError(RuntimeError):
    """Base scanner error."""


class ToolNotInstalledError(ScannerError):
    """Raised when an external tool is unavailable."""


class CommandExecutionError(ScannerError):
    """Raised when a subprocess command fails."""


@dataclass(slots=True)
class SeveritySummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.info
            + self.unknown
        )

    def add(self, severity: str) -> None:
        normalized = severity.strip().lower()
        bucket = normalized if normalized in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "unknown",
        } else "unknown"
        setattr(self, bucket, getattr(self, bucket) + 1)

    def as_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "unknown": self.unknown,
            "total": self.total,
        }


def summarize_issues(issues: list[dict[str, Any]]) -> dict[str, int]:
    summary = SeveritySummary()
    for issue in issues:
        summary.add(issue.get("severity", "unknown"))
    return summary.as_dict()


def calculate_security_score(issues: list[dict[str, Any]]) -> int:
    summary = SeveritySummary()
    for issue in issues:
        summary.add(issue.get("severity", "unknown"))

    # Tanglish: score ellam instant-a zero ஆகாமல் useful range la irukkanum.
    severity_penalty = (
        min(summary.critical, 3) * 14
        + min(summary.high, 8) * 5
        + min(summary.medium, 12) * 2
        + min(summary.low, 15) * 0.5
        + min(summary.unknown, 8) * 1
    )

    volume_penalty = min(summary.total, 40) * 0.35
    penalty = min(82, severity_penalty + volume_penalty)

    score = 100 - penalty
    return int(max(18, math.floor(score)))


def ensure_binary(binary: str) -> None:
    if shutil.which(binary) is None:
        raise ToolNotInstalledError(f"Required binary '{binary}' was not found in PATH.")


def run_command(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError(
            f"Command timed out after {timeout}s: {' '.join(command)}"
        ) from exc
    except OSError as exc:
        raise CommandExecutionError(f"Unable to execute {' '.join(command)}: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Unknown command error.").strip()
        raise CommandExecutionError(f"Command failed: {' '.join(command)}: {detail}")

    return completed


def run_json_command(command: list[str], timeout: int = 60) -> Any:
    completed = run_command(command, timeout=timeout)
    try:
        return json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise CommandExecutionError(
            f"Command did not return valid JSON: {' '.join(command)}"
        ) from exc


def safe_text_sample(path: Path, max_bytes: int = 1024 * 1024) -> str:
    try:
        raw = path.read_bytes()[:max_bytes]
    except OSError:
        return ""

    if b"\x00" in raw:
        return ""

    return raw.decode("utf-8", errors="ignore")
