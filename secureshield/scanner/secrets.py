"""Filesystem secrets detection using patterns and entropy."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .common import ScannerError, safe_text_sample, summarize_issues


PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "stripe_live_key": r"sk_live_[A-Za-z0-9]{16,}",
    "openai_key": r"sk-[A-Za-z0-9]{20,}",
    "google_api_key": r"AIza[0-9A-Za-z_-]{30,}",
    "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "password_assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "token_assignment": r"(?i)(token|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}


class SecretsScanner:
    """Scan project files for embedded secrets."""

    def __init__(self, max_file_size: int = 1024 * 1024) -> None:
        self.max_file_size = max_file_size

    def scan(self, path: str) -> dict[str, Any]:
        root = Path(path).expanduser().resolve()
        if not root.exists():
            raise ScannerError(f"Path '{path}' does not exist.")

        findings: list[dict[str, Any]] = []
        file_count = 0
        for file_path in self._iter_files(root):
            file_count += 1
            text = safe_text_sample(file_path, self.max_file_size)
            if not text:
                continue
            findings.extend(self._pattern_findings(file_path, text))
            findings.extend(self._entropy_findings(file_path, text))

        findings.sort(key=lambda item: (self._severity_rank(item["severity"]), item["path"]))
        return {
            "module": "secrets",
            "target": str(root),
            "file_count": file_count,
            "findings": findings,
            "summary": summarize_issues(findings),
        }

    def _iter_files(self, root: Path):
        ignored = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
        ignored_files = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
        if root.is_file():
            if root.name not in ignored_files:
                yield root
            return

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.name in ignored_files:
                continue
            if any(part in ignored for part in path.parts):
                continue
            yield path

    def _pattern_findings(self, path: Path, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for secret_type, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                findings.append(
                    {
                        "id": f"SECRET-{secret_type.upper()}",
                        "title": f"Potential {secret_type.replace('_', ' ')} detected",
                        "severity": "HIGH",
                        "path": str(path),
                        "line": text.count("\n", 0, match.start()) + 1,
                        "match": self._mask(match.group(0)),
                        "description": "A hard-coded secret pattern was detected in this file.",
                        "remediation": "Move secrets to environment variables, vaults, or secret managers.",
                    }
                )
        return findings

    def _entropy_findings(self, path: Path, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for match in re.finditer(r"[A-Za-z0-9+/=_-]{24,}", text):
            candidate = match.group(0)
            if self._is_noise_candidate(candidate):
                continue
            if self._shannon_entropy(candidate) >= 4.5 and not candidate.isdigit():
                findings.append(
                    {
                        "id": "SECRET-ENTROPY",
                        "title": "High-entropy string detected",
                        "severity": "MEDIUM",
                        "path": str(path),
                        "line": text.count("\n", 0, match.start()) + 1,
                        "match": self._mask(candidate),
                        "description": "A random-looking string may represent a hidden secret or token.",
                        "remediation": "Review whether this value is a token, key, hash, or generated artifact.",
                    }
                )
        return findings

    def _shannon_entropy(self, value: str) -> float:
        probabilities = [float(value.count(char)) / len(value) for char in set(value)]
        return -sum(probability * math.log(probability, 2) for probability in probabilities)

    def _is_noise_candidate(self, value: str) -> bool:
        lowered = value.lower()
        if lowered.startswith(("sha256-", "sha384-", "sha512-")):
            return True
        if "change-me" in lowered or "example" in lowered or "placeholder" in lowered:
            return True
        if value.isupper() and any(token in value for token in ("PASSWORD", "SECRET", "TOKEN", "API_KEY")):
            return True
        return False

    def _mask(self, value: str) -> str:
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"

    def _severity_rank(self, severity: str) -> int:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return order.get(severity.upper(), 5)
