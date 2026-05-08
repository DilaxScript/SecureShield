"""Lightweight auth helpers for local SecureShield sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from secureshield.config import APP_SECRET_KEY


def hash_password(password: str, *, salt: str | None = None) -> str:
    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_value.encode("utf-8"),
        200_000,
    ).hex()
    return f"{salt_value}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_value, digest = stored_hash.split("$", 1)
    except ValueError:
        return False
    expected = hash_password(password, salt=salt_value).split("$", 1)[1]
    return hmac.compare_digest(digest, expected)


def issue_token(user: dict[str, Any], *, ttl_seconds: int = 60 * 60 * 12) -> str:
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user.get("role", "analyst"),
        "exp": int(time.time()) + ttl_seconds,
        "nonce": secrets.token_hex(8),
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _sign(body)
    return f"{body}.{signature}"


def decode_token(token: str) -> dict[str, Any]:
    try:
        body, signature = token.split(".", 1)
    except ValueError as exc:
        raise ValueError("Invalid token format.") from exc
    expected = _sign(body)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid token signature.")
    try:
        payload = json.loads(_b64decode(body))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid token payload.") from exc
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("Token expired.")
    if "sub" not in payload:
        raise ValueError("Token subject is missing.")
    return payload


def _sign(body: str) -> str:
    secret = APP_SECRET_KEY.encode("utf-8")
    return hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
