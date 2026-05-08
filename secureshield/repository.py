"""Persistence helpers for scan history and normalized artifacts."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from secureshield.db import SessionLocal, init_database
from secureshield.models import (
    AIRecommendation,
    ComplianceFinding,
    ImageAsset,
    ReportArtifact,
    RuntimeEvent,
    ScanRecord,
    ScanJob,
    SecretFinding,
    UserAccount,
    VulnerabilityFinding,
)


def save_scan_result(
    *,
    scan_type: str,
    target: str,
    result: dict[str, Any],
    source_path: str | None = None,
    owner: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_database()
    with SessionLocal() as session:
        stored_result = dict(result)
        if owner:
            stored_result["_owner"] = {
                "id": owner.get("id"),
                "username": owner.get("username"),
            }
        record = ScanRecord(
            scan_type=scan_type,
            target=target,
            source_path=source_path,
            owner_user_id=owner.get("id") if owner else None,
            status=result.get("status", "completed"),
            security_score=result.get("security_score"),
            summary=result.get("summary", {}),
            result=stored_result,
        )
        session.add(record)
        session.flush()

        _save_image_asset(session, record=record)
        _save_normalized_findings(session, record=record, result=result)

        session.commit()
        session.refresh(record)
        return serialize_scan_record(record)


def save_ai_recommendation(
    *,
    interaction_type: str,
    finding_id: str | None,
    image_name: str | None,
    response: dict[str, Any],
    prompt: str | None = None,
    scan_record_id: int | None = None,
) -> dict[str, Any]:
    init_database()
    with SessionLocal() as session:
        entry = AIRecommendation(
            scan_record_id=scan_record_id,
            image_name=image_name,
            finding_id=finding_id,
            interaction_type=interaction_type,
            prompt=prompt,
            response=response,
        )
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return serialize_ai_recommendation(entry)


def save_report_artifact(
    *,
    report_type: str,
    format: str,
    filters: dict[str, Any],
    content: str,
    scan_record_id: int | None = None,
) -> dict[str, Any]:
    init_database()
    with SessionLocal() as session:
        artifact = ReportArtifact(
            scan_record_id=scan_record_id,
            report_type=report_type,
            format=format,
            filters=filters,
            content=content,
        )
        session.add(artifact)
        session.commit()
        session.refresh(artifact)
        return serialize_report_artifact(artifact)


def create_user(
    *,
    username: str,
    password_hash: str,
    role: str = "analyst",
    full_name: str | None = None,
    email: str | None = None,
    job_title: str | None = None,
    is_active: bool = True,
) -> dict[str, Any]:
    init_database()
    with SessionLocal() as session:
        existing = session.execute(select(UserAccount).where(UserAccount.username == username)).scalar_one_or_none()
        if existing:
            raise ValueError("Username already exists.")
        user = UserAccount(
            username=username,
            password_hash=password_hash,
            role=role,
            full_name=full_name or None,
            email=email or None,
            job_title=job_title or None,
            is_active=is_active,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return serialize_user(user)


def get_user_by_username(username: str) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        user = session.execute(select(UserAccount).where(UserAccount.username == username)).scalar_one_or_none()
        if not user:
            return None
        return serialize_user(user, include_secret=True)


def get_user(user_id: int) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        user = session.get(UserAccount, user_id)
        if not user:
            return None
        return serialize_user(user)


def list_users() -> list[dict[str, Any]]:
    init_database()
    with SessionLocal() as session:
        stmt = select(UserAccount).order_by(UserAccount.created_at.desc(), UserAccount.id.desc())
        return [serialize_user(user) for user in session.execute(stmt).scalars().all()]


def update_user_profile(
    user_id: int,
    *,
    full_name: str | None = None,
    email: str | None = None,
    job_title: str | None = None,
) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        user = session.get(UserAccount, user_id)
        if not user:
            return None
        user.full_name = full_name or None
        user.email = email or None
        user.job_title = job_title or None
        session.commit()
        session.refresh(user)
        return serialize_user(user)


def update_user_admin(
    user_id: int,
    *,
    role: str | None = None,
    full_name: str | None = None,
    email: str | None = None,
    job_title: str | None = None,
    is_active: bool | None = None,
) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        user = session.get(UserAccount, user_id)
        if not user:
            return None
        if role is not None:
            user.role = role
        if full_name is not None:
            user.full_name = full_name or None
        if email is not None:
            user.email = email or None
        if job_title is not None:
            user.job_title = job_title or None
        if is_active is not None:
            user.is_active = is_active
        session.commit()
        session.refresh(user)
        return serialize_user(user)


def update_user_password(user_id: int, *, password_hash: str) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        user = session.get(UserAccount, user_id)
        if not user:
            return None
        user.password_hash = password_hash
        session.commit()
        session.refresh(user)
        return serialize_user(user)


def delete_user(user_id: int) -> bool:
    init_database()
    with SessionLocal() as session:
        user = session.get(UserAccount, user_id)
        if not user:
            return False
        for record in session.execute(select(ScanRecord).where(ScanRecord.owner_user_id == user_id)).scalars().all():
            record.owner_user_id = None
        for job in session.execute(select(ScanJob).where(ScanJob.requested_by == user_id)).scalars().all():
            job.requested_by = None
        session.delete(user)
        session.commit()
        return True


def create_scan_job(
    *,
    scan_type: str,
    target: str,
    source_path: str | None = None,
    requested_by: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_database()
    with SessionLocal() as session:
        job = ScanJob(
            scan_type=scan_type,
            target=target,
            source_path=source_path,
            requested_by=requested_by,
            status="queued",
            progress=0,
            job_metadata=metadata or {},
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return serialize_scan_job(job)


def update_scan_job(
    job_id: int,
    *,
    status: str | None = None,
    progress: int | None = None,
    error: str | None = None,
    result_record_id: int | None = None,
    metadata_updates: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return None
        if status is not None:
            job.status = status
        if progress is not None:
            job.progress = progress
        if error is not None:
            job.error = error
        if result_record_id is not None:
            job.result_record_id = result_record_id
        if metadata_updates:
            job.job_metadata = {**(job.job_metadata or {}), **metadata_updates}
        session.commit()
        session.refresh(job)
        return serialize_scan_job(job)


def get_scan_job(job_id: int) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return None
        return serialize_scan_job(job)


def list_scan_jobs(limit: int = 20) -> list[dict[str, Any]]:
    init_database()
    with SessionLocal() as session:
        stmt = select(ScanJob).order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(limit)
        return [serialize_scan_job(item) for item in session.execute(stmt).scalars().all()]


def find_latest_scan_record(scan_type: str, target: str, owner_id: int | None = None) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        stmt = select(ScanRecord).where(ScanRecord.scan_type == scan_type, ScanRecord.target == target)
        if owner_id is None:
            stmt = stmt.where(ScanRecord.owner_user_id.is_(None))
        else:
            stmt = stmt.where(ScanRecord.owner_user_id == owner_id)
        stmt = stmt.order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc()).limit(1)
        record = session.execute(stmt).scalar_one_or_none()
        if record:
            payload = serialize_scan_record(record)
            payload["result"] = record.result
            return payload
        return None


def list_scan_history(
    limit: int = 20,
    scan_type: str | None = None,
    *,
    include_result: bool = False,
    owner_id: int | None = None,
    all_owners: bool = False,
) -> list[dict[str, Any]]:
    init_database()
    with SessionLocal() as session:
        stmt = select(ScanRecord).order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
        if scan_type:
            stmt = stmt.where(ScanRecord.scan_type == scan_type)
        if all_owners:
            pass
        elif owner_id is None:
            stmt = stmt.where(ScanRecord.owner_user_id.is_(None))
        else:
            stmt = stmt.where(ScanRecord.owner_user_id == owner_id)
        stmt = stmt.order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
        records = session.execute(stmt).scalars().all()
        unique_records: list[dict[str, Any]] = []
        seen_targets: set[tuple[str, str]] = set()
        for record in records:
            key = (record.scan_type, record.target)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            payload = serialize_scan_record(record)
            if include_result:
                payload["result"] = record.result
            unique_records.append(payload)
            if len(unique_records) >= limit:
                break
        return unique_records


def get_scan_record(record_id: int, owner_id: int | None = None, *, all_owners: bool = False) -> dict[str, Any] | None:
    init_database()
    with SessionLocal() as session:
        record = session.get(ScanRecord, record_id)
        if not record:
            return None
        if all_owners:
            pass
        elif owner_id is None and record.owner_user_id is not None:
            return None
        if owner_id is not None and record.owner_user_id != owner_id:
            return None
        payload = serialize_scan_record(record)
        payload["result"] = record.result
        payload["normalized_counts"] = _normalized_counts(session, record.id)
        return payload


def list_report_artifacts(limit: int = 20) -> list[dict[str, Any]]:
    init_database()
    with SessionLocal() as session:
        stmt = select(ReportArtifact).order_by(ReportArtifact.created_at.desc(), ReportArtifact.id.desc()).limit(limit)
        return [serialize_report_artifact(item) for item in session.execute(stmt).scalars().all()]


def serialize_scan_record(record: ScanRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "scan_type": record.scan_type,
        "target": record.target,
        "source_path": record.source_path,
        "owner_user_id": record.owner_user_id,
        "status": record.status,
        "security_score": record.security_score,
        "summary": record.summary,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


def serialize_user(user: UserAccount, *, include_secret: bool = False) -> dict[str, Any]:
    payload = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "full_name": user.full_name,
        "email": user.email,
        "job_title": user.job_title,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
    if include_secret:
        payload["password_hash"] = user.password_hash
    return payload


def serialize_scan_job(job: ScanJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "scan_type": job.scan_type,
        "target": job.target,
        "source_path": job.source_path,
        "requested_by": job.requested_by,
        "status": job.status,
        "progress": job.progress,
        "error": job.error,
        "result_record_id": job.result_record_id,
        "metadata": job.job_metadata or {},
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
    }


def serialize_ai_recommendation(entry: AIRecommendation) -> dict[str, Any]:
    return {
        "id": entry.id,
        "scan_record_id": entry.scan_record_id,
        "image_name": entry.image_name,
        "finding_id": entry.finding_id,
        "interaction_type": entry.interaction_type,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def serialize_report_artifact(entry: ReportArtifact) -> dict[str, Any]:
    return {
        "id": entry.id,
        "scan_record_id": entry.scan_record_id,
        "report_type": entry.report_type,
        "format": entry.format,
        "filters": entry.filters,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def _save_image_asset(session: SessionLocal, *, record: ScanRecord) -> None:
    session.add(
        ImageAsset(
            scan_record_id=record.id,
            image_name=record.target,
            source_path=record.source_path,
            scan_type=record.scan_type,
            status=record.status,
        )
    )


def _save_normalized_findings(session: SessionLocal, *, record: ScanRecord, result: dict[str, Any]) -> None:
    for vulnerability in _extract_vulnerabilities(result):
        session.add(VulnerabilityFinding(scan_record_id=record.id, **vulnerability))

    for finding in _extract_compliance_findings(result):
        session.add(ComplianceFinding(scan_record_id=record.id, **finding))

    for finding in _extract_secret_findings(result):
        session.add(SecretFinding(scan_record_id=record.id, **finding))

    for event in _extract_runtime_events(result):
        session.add(RuntimeEvent(scan_record_id=record.id, **event))


def _extract_vulnerabilities(result: dict[str, Any]) -> list[dict[str, Any]]:
    issues = result.get("issues") or []
    items: list[dict[str, Any]] = []
    for issue in issues:
        if issue.get("module") != "cve":
            continue
        metadata = issue.get("metadata") or {}
        items.append(
            {
                "cve_id": issue.get("id") or metadata.get("cve_id") or "UNKNOWN",
                "severity": issue.get("severity", "UNKNOWN"),
                "title": issue.get("title") or issue.get("id") or "Untitled finding",
                "target": issue.get("target") or metadata.get("target") or "unknown",
                "package_name": metadata.get("pkg_name"),
                "installed_version": metadata.get("installed_version"),
                "fixed_version": metadata.get("fixed_version"),
                "description": issue.get("description") or metadata.get("description"),
                "raw": issue,
            }
        )
    return items


def _extract_compliance_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    issues = result.get("issues") or []
    items: list[dict[str, Any]] = []
    for issue in issues:
        module = issue.get("module")
        if module not in {"cis", "supply_chain"}:
            continue
        items.append(
            {
                "module": module,
                "check_id": issue.get("id") or "UNKNOWN",
                "title": issue.get("title") or issue.get("id") or "Untitled finding",
                "severity": issue.get("severity", "UNKNOWN"),
                "status": issue.get("status", "fail"),
                "target": issue.get("target") or "unknown",
                "remediation": issue.get("remediation"),
                "details": issue.get("metadata") or {},
            }
        )
    return items


def _extract_secret_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    secrets = ((result.get("modules") or {}).get("secrets") or {}).get("findings") or []
    items: list[dict[str, Any]] = []
    for finding in secrets:
        items.append(
            {
                "rule_id": finding.get("id") or finding.get("rule_id") or "UNKNOWN",
                "severity": finding.get("severity", "UNKNOWN"),
                "title": finding.get("title") or finding.get("description") or "Secret finding",
                "target": finding.get("target") or finding.get("path") or "unknown",
                "remediation": finding.get("remediation"),
                "details": finding.get("metadata") or finding,
            }
        )
    return items


def _extract_runtime_events(result: dict[str, Any]) -> list[dict[str, Any]]:
    runtime = ((result.get("modules") or {}).get("runtime") or {}).get("checks") or []
    items: list[dict[str, Any]] = []
    for finding in runtime:
        items.append(
            {
                "event_id": finding.get("id") or "UNKNOWN",
                "severity": finding.get("severity", "UNKNOWN"),
                "title": finding.get("title") or finding.get("description") or "Runtime event",
                "status": finding.get("status", "unknown"),
                "target": finding.get("target") or "unknown",
                "remediation": finding.get("remediation"),
                "details": finding.get("metadata") or {},
            }
        )
    return items


def _normalized_counts(session: SessionLocal, scan_record_id: int) -> dict[str, int]:
    return {
        "images": _count_for(session, ImageAsset, scan_record_id),
        "vulnerabilities": _count_for(session, VulnerabilityFinding, scan_record_id),
        "compliance_results": _count_for(session, ComplianceFinding, scan_record_id),
        "secret_findings": _count_for(session, SecretFinding, scan_record_id),
        "runtime_events": _count_for(session, RuntimeEvent, scan_record_id),
    }


def _count_for(session: SessionLocal, model: type[Any], scan_record_id: int) -> int:
    stmt = select(model).where(model.scan_record_id == scan_record_id)
    return len(session.execute(stmt).scalars().all())
