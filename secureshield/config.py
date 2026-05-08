"""Application configuration for SecureShield."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def _load_local_env() -> None:
    """Load simple KEY=VALUE pairs from a local .env file if present."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _normalized_scheme(value: str) -> str:
    mapping = {
        "sqlite": "sqlite",
        "sqlite3": "sqlite",
        "pgsql": "postgresql+psycopg",
        "postgres": "postgresql+psycopg",
        "postgresql": "postgresql+psycopg",
        "postgresql+psycopg": "postgresql+psycopg",
    }
    return mapping.get(value.lower(), value)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _build_database_url(
    *,
    connection: str,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
) -> str:
    scheme = _normalized_scheme(connection)
    if scheme == "sqlite":
        db_path = Path(database)
        if not db_path.is_absolute():
            db_path = Path(__file__).resolve().parent.parent / db_path
        return f"sqlite:///{db_path}"

    return f"{scheme}://{username}:{password}@{host}:{port}/{database}"


_load_local_env()

# Database config
DB_CONNECTION = os.getenv("DB_CONNECTION", "sqlite")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_DATABASE = os.getenv("DB_DATABASE", "secureshield.db")
DB_USERNAME = os.getenv("DB_USERNAME", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    _build_database_url(
        connection=DB_CONNECTION,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_DATABASE,
        username=DB_USERNAME,
        password=DB_PASSWORD,
    ),
)

# Gemini AI config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")

# Auth and async settings
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY") or secrets.token_urlsafe(32)
REDIS_URL = os.getenv("REDIS_URL", "")
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "")

# Trivy config
TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "")
TRIVY_IMAGE_SRC = os.getenv("TRIVY_IMAGE_SRC", "")
TRIVY_SKIP_DB_UPDATE = _env_flag("TRIVY_SKIP_DB_UPDATE", default=False)
TRIVY_OFFLINE_SCAN = _env_flag("TRIVY_OFFLINE_SCAN", default=False)

# API filesystem scan roots. CLI scans are intentionally unaffected.
SCAN_ALLOWED_ROOTS = os.getenv("SCAN_ALLOWED_ROOTS", str(Path(__file__).resolve().parent.parent))
