"""Report helpers for exports and aggregate summaries."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from secureshield.repository import list_scan_history
from secureshield.repository import save_report_artifact


def build_report_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    aggregate = {
        "total_records": len(records),
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "scan_types": {},
    }

    for record in records:
        summary = record.get("summary") or {}
        aggregate["total_findings"] += summary.get("total", 0)
        for key in ("critical", "high", "medium", "low", "info", "unknown"):
            aggregate[key] += summary.get(key, 0)
        scan_type = record.get("scan_type") or "unknown"
        aggregate["scan_types"][scan_type] = aggregate["scan_types"].get(scan_type, 0) + 1

    return aggregate


def get_report_payload(
    limit: int = 50,
    scan_type: str | None = None,
    owner_id: int | None = None,
    all_owners: bool = False,
) -> dict[str, Any]:
    records = list_scan_history(
        limit=limit,
        scan_type=scan_type,
        include_result=True,
        owner_id=owner_id,
        all_owners=all_owners,
    )
    return {
        "filters": {"limit": limit, "scan_type": scan_type},
        "summary": build_report_summary(records),
        "records": records,
        "vulnerabilities": build_vulnerability_report(records),
    }


def build_vulnerability_report(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        result = record.get("result") or {}
        for issue in result.get("issues") or []:
            if issue.get("module") != "cve":
                continue
            metadata = issue.get("metadata") or {}
            rows.append(
                {
                    "record_id": record.get("id"),
                    "scan_type": record.get("scan_type"),
                    "target_image": record.get("target"),
                    "created_at": record.get("created_at"),
                    "security_score": record.get("security_score"),
                    "cve_id": issue.get("id") or metadata.get("cve_id") or "UNKNOWN",
                    "severity": issue.get("severity", "UNKNOWN"),
                    "title": issue.get("title") or issue.get("id") or "Untitled finding",
                    "target": issue.get("target") or metadata.get("target") or "unknown",
                    "package_name": metadata.get("pkg_name") or metadata.get("package_name"),
                    "installed_version": metadata.get("installed_version"),
                    "fixed_version": metadata.get("fixed_version"),
                    "description": issue.get("description") or metadata.get("description") or "",
                }
            )
    return rows


def export_report_json(
    limit: int = 50,
    scan_type: str | None = None,
    owner_id: int | None = None,
    all_owners: bool = False,
) -> str:
    payload = json.dumps(
        get_report_payload(limit=limit, scan_type=scan_type, owner_id=owner_id, all_owners=all_owners),
        indent=2,
    ) + "\n"
    save_report_artifact(
        report_type="vulnerability_report",
        format="json",
        filters={"limit": limit, "scan_type": scan_type},
        content=payload,
    )
    return payload


def export_report_csv(
    limit: int = 50,
    scan_type: str | None = None,
    owner_id: int | None = None,
    all_owners: bool = False,
) -> str:
    records = list_scan_history(
        limit=limit,
        scan_type=scan_type,
        include_result=True,
        owner_id=owner_id,
        all_owners=all_owners,
    )
    vulnerabilities = build_vulnerability_report(records)
    output = io.StringIO()
    fieldnames = [
        "record_id",
        "scan_type",
        "target_image",
        "created_at",
        "security_score",
        "cve_id",
        "severity",
        "title",
        "target",
        "package_name",
        "installed_version",
        "fixed_version",
        "description",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in vulnerabilities:
        writer.writerow(row)
    payload = output.getvalue()
    save_report_artifact(
        report_type="vulnerability_report",
        format="csv",
        filters={"limit": limit, "scan_type": scan_type},
        content=payload,
    )
    return payload


def export_report_markdown(
    limit: int = 50,
    scan_type: str | None = None,
    owner_id: int | None = None,
    all_owners: bool = False,
) -> str:
    records = list_scan_history(
        limit=limit,
        scan_type=scan_type,
        include_result=True,
        owner_id=owner_id,
        all_owners=all_owners,
    )
    vulnerabilities = build_vulnerability_report(records)
    lines = [
        "| Record ID | Type | Target | Severity | CVE | Package | Fixed Version |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in vulnerabilities:
        lines.append(
            "| {record_id} | {scan_type} | {target_image} | {severity} | {cve_id} | {package_name} | {fixed_version} |".format(
                record_id=row.get("record_id", ""),
                scan_type=row.get("scan_type", ""),
                target_image=row.get("target_image", ""),
                severity=row.get("severity", ""),
                cve_id=row.get("cve_id", ""),
                package_name=row.get("package_name", "") or "-",
                fixed_version=row.get("fixed_version", "") or "-",
            )
        )
    payload = "\n".join(lines) + "\n"
    save_report_artifact(
        report_type="vulnerability_report",
        format="md",
        filters={"limit": limit, "scan_type": scan_type},
        content=payload,
    )
    return payload
