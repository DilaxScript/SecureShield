"""Database engine and session management."""

from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from secureshield.config import DATABASE_URL


engine_kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite:///"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_database() -> None:
    from secureshield.models import Base

    Base.metadata.create_all(bind=engine)
    _migrate_user_profile_columns()
    _migrate_scan_record_owner_column()


def _migrate_user_profile_columns() -> None:
    inspector = inspect(engine)
    if "secureshield_users" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("secureshield_users")}
    profile_columns = {
        "full_name": "VARCHAR(120)",
        "email": "VARCHAR(255)",
        "job_title": "VARCHAR(120)",
        "is_active": "BOOLEAN NOT NULL DEFAULT 1",
    }
    with engine.begin() as connection:
        for column_name, column_type in profile_columns.items():
            if column_name not in columns:
                connection.execute(text(f"ALTER TABLE secureshield_users ADD COLUMN {column_name} {column_type}"))


def _migrate_scan_record_owner_column() -> None:
    from secureshield.models import ScanRecord

    inspector = inspect(engine)
    if "secureshield_scan_records" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("secureshield_scan_records")}
    if "owner_user_id" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE secureshield_scan_records ADD COLUMN owner_user_id INTEGER"))

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_secureshield_scan_records_owner_user_id "
                "ON secureshield_scan_records (owner_user_id)"
            )
        )
        connection.execute(
            text(
                """
                UPDATE secureshield_scan_records
                SET owner_user_id = (
                    SELECT requested_by
                    FROM secureshield_scan_jobs
                    WHERE secureshield_scan_jobs.result_record_id = secureshield_scan_records.id
                      AND secureshield_scan_jobs.requested_by IS NOT NULL
                    ORDER BY secureshield_scan_jobs.id DESC
                    LIMIT 1
                )
                WHERE owner_user_id IS NULL
                """
            )
        )

    with SessionLocal() as session:
        records = session.query(ScanRecord).filter(ScanRecord.owner_user_id.is_(None)).all()
        updated = False
        for record in records:
            owner = (record.result or {}).get("_owner") or {}
            owner_id = owner.get("id")
            if owner_id in (None, ""):
                continue
            record.owner_user_id = int(owner_id)
            updated = True
        if updated:
            session.commit()


def database_health() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database_url": DATABASE_URL.rsplit("@", 1)[-1]}
