"""SQLAlchemy models for scan persistence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative model."""


class UserAccount(Base):
    """Stores dashboard user accounts."""

    __tablename__ = "secureshield_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="analyst", index=True)
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_title: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class ScanJob(Base):
    """Stores asynchronous scan requests and lifecycle state."""

    __tablename__ = "secureshield_scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[str] = mapped_column(String(50), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    source_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("secureshield_users.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("secureshield_scan_records.id"),
        nullable=True,
        index=True,
    )
    job_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ScanRecord(Base):
    """Stores one completed scan payload."""

    __tablename__ = "secureshield_scan_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[str] = mapped_column(String(50), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    source_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("secureshield_users.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="completed")
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class ImageAsset(Base):
    """Normalized image/job metadata for each saved scan."""

    __tablename__ = "secureshield_image_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int] = mapped_column(ForeignKey("secureshield_scan_records.id"), index=True)
    image_name: Mapped[str] = mapped_column(String(255), index=True)
    source_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    scan_type: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50), default="completed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class VulnerabilityFinding(Base):
    """Stores normalized CVE findings."""

    __tablename__ = "secureshield_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int] = mapped_column(ForeignKey("secureshield_scan_records.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(512))
    target: Mapped[str] = mapped_column(String(512), index=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class ComplianceFinding(Base):
    """Stores CIS and supply-chain style normalized findings."""

    __tablename__ = "secureshield_compliance_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int] = mapped_column(ForeignKey("secureshield_scan_records.id"), index=True)
    module: Mapped[str] = mapped_column(String(50), index=True)
    check_id: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class SecretFinding(Base):
    """Stores normalized secret scan findings."""

    __tablename__ = "secureshield_secret_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int] = mapped_column(ForeignKey("secureshield_scan_records.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(512))
    target: Mapped[str] = mapped_column(String(1024), index=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class RuntimeEvent(Base):
    """Stores normalized runtime security findings/events."""

    __tablename__ = "secureshield_runtime_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int] = mapped_column(ForeignKey("secureshield_scan_records.id"), index=True)
    event_id: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(30), index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class AIRecommendation(Base):
    """Stores AI remediation/chat outputs for audit and history."""

    __tablename__ = "secureshield_ai_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int | None] = mapped_column(ForeignKey("secureshield_scan_records.id"), nullable=True, index=True)
    image_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    interaction_type: Mapped[str] = mapped_column(String(30), index=True)
    prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    response: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class ReportArtifact(Base):
    """Stores generated report metadata and payload snapshots."""

    __tablename__ = "secureshield_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_record_id: Mapped[int | None] = mapped_column(ForeignKey("secureshield_scan_records.id"), nullable=True, index=True)
    report_type: Mapped[str] = mapped_column(String(50), index=True)
    format: Mapped[str] = mapped_column(String(20), index=True)
    filters: Mapped[dict] = mapped_column(JSON)
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
