"""Gemini-backed remediation guidance service."""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib import error, request

from secureshield.config import GEMINI_API_KEY, GEMINI_MODEL


logger = logging.getLogger(__name__)


class AIServiceError(RuntimeError):
    """Base AI service error."""


class AIConfigError(AIServiceError):
    """Raised when Gemini credentials are missing."""


class GeminiRemediationService:
    """Generate remediation guidance from scan findings."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int = 45,
    ) -> None:
        self.api_key = api_key or GEMINI_API_KEY
        self.model = model or GEMINI_MODEL
        self.timeout = timeout

    def remediate(self, finding: dict[str, Any], image: str | None = None) -> dict[str, Any]:
        if not self.api_key:
            raise AIConfigError("GEMINI_API_KEY is not configured.")

        prompt = self._build_prompt(finding, image=image)
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt,
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.9,
                "responseMimeType": "application/json",
            },
        }

        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        http_request = request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-goog-api-key": self.api_key,
            },
            method="POST",
        )

        raw = self._perform_request(http_request)
        text = self._extract_text(raw)
        parsed = self._coerce_response(text, finding)

        parsed["disclaimer"] = "AI-generated guidance. Verify before production use."
        return parsed

    def chat(
        self,
        *,
        finding: dict[str, Any],
        question: str,
        image: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        if not self.api_key:
            raise AIConfigError("GEMINI_API_KEY is not configured.")

        prompt = self._build_chat_prompt(
            finding=finding,
            question=question,
            image=image,
            history=history or [],
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt,
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "topP": 0.9,
            },
        }
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        http_request = request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-goog-api-key": self.api_key,
            },
            method="POST",
        )

        raw = self._perform_request(http_request)
        text = self._extract_text(raw).strip()
        return {
            "answer": text,
            "disclaimer": "AI-generated guidance. Verify before production use.",
        }

    def _perform_request(self, http_request: request.Request) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                with request.urlopen(http_request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="ignore")
                logger.warning("Gemini HTTP error on attempt %s: %s %s", attempt + 1, exc.code, body)
                last_error = AIServiceError(f"Gemini API request failed: HTTP {exc.code}: {body}")
                if exc.code < 500 or attempt == 1:
                    raise last_error from exc
            except error.URLError as exc:
                logger.warning("Gemini URL error on attempt %s: %s", attempt + 1, exc.reason)
                last_error = AIServiceError(f"Gemini API is unreachable: {exc.reason}")
                if attempt == 1:
                    raise last_error from exc
            except json.JSONDecodeError as exc:
                logger.warning("Gemini returned invalid JSON envelope on attempt %s", attempt + 1)
                last_error = AIServiceError("Gemini returned invalid JSON.")
                if attempt == 1:
                    raise last_error from exc

            time.sleep(0.5)

        if last_error:
            raise last_error
        raise AIServiceError("Gemini request failed unexpectedly.")

    def _coerce_response(self, text: str, finding: dict[str, Any]) -> dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.info("Gemini returned plain text response; using fallback coercion.")
            return self._fallback_from_text(text, finding)

    def _extract_text(self, payload: dict[str, Any]) -> str:
        candidates = payload.get("candidates") or []
        if not candidates:
            logger.warning("Gemini returned no candidates: %s", payload)
            raise AIServiceError("Gemini returned no candidates.")
        parts = ((candidates[0].get("content") or {}).get("parts")) or []
        if not parts or "text" not in parts[0]:
            logger.warning("Gemini returned no text content: %s", payload)
            raise AIServiceError("Gemini returned no text content.")
        return parts[0]["text"]

    def _build_prompt(self, finding: dict[str, Any], image: str | None = None) -> str:
        return (
            "You are SecureShield AI, a container security remediation assistant.\n"
            "Use only the provided finding context.\n"
            "Do not invent package versions, CVEs, or unsupported claims.\n"
            "Return strict JSON with keys: summary, risk, remediation_steps, safe_example, priority.\n"
            "remediation_steps must be an array of short strings.\n"
            f"Container image: {image or finding.get('target') or 'unknown'}\n"
            f"Finding JSON: {json.dumps(finding, ensure_ascii=True)}\n"
            "Explain the issue in simple language, mention container-specific risk, and suggest safe remediation."
        )

    def _build_chat_prompt(
        self,
        *,
        finding: dict[str, Any],
        question: str,
        image: str | None = None,
        history: list[dict[str, str]],
    ) -> str:
        serialized_history = json.dumps(history[-6:], ensure_ascii=True)
        return (
            "You are SecureShield AI chat, a container security support assistant.\n"
            "Answer the user's question using only the supplied finding context.\n"
            "Do not invent CVEs, versions, exploit claims, or package names.\n"
            "Keep the answer concise, practical, and focused on remediation/safety.\n"
            f"Container image: {image or finding.get('target') or 'unknown'}\n"
            f"Finding JSON: {json.dumps(finding, ensure_ascii=True)}\n"
            f"Recent chat history JSON: {serialized_history}\n"
            f"User question: {question}\n"
            "Respond in plain text with actionable guidance."
        )

    def _fallback_from_text(self, text: str, finding: dict[str, Any]) -> dict[str, Any]:
        fixed_version = (
            finding.get("fixed_version")
            or (finding.get("metadata") or {}).get("fixed_version")
            or "the latest patched version"
        )
        package_name = (
            finding.get("pkg_name")
            or (finding.get("metadata") or {}).get("pkg_name")
            or "the affected package"
        )
        return {
            "summary": text.strip(),
            "risk": f"{finding.get('severity', 'UNKNOWN')} severity finding in container context.",
            "remediation_steps": [
                f"Review the finding impact for {finding.get('target', 'the scanned target')}.",
                f"Upgrade {package_name} to {fixed_version} if a fix is available.",
                "Rebuild the image and rescan before deployment.",
            ],
            "safe_example": f"Update {package_name} and rebuild the container image.",
            "priority": "Fix now" if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"} else "Plan remediation",
        }
