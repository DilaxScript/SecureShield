"""Asynchronous scan job helpers."""

from __future__ import annotations

import threading
from typing import Any

from secureshield.cache import cache_store
from secureshield.repository import get_scan_job, get_user, save_scan_result, update_scan_job
from secureshield.scanner import ScannerError, SecureShieldScanner


def start_full_scan_job(job_id: int, *, image: str, source_path: str | None = None, timeout: int = 300) -> None:
    worker = threading.Thread(
        target=_run_full_scan_job,
        kwargs={"job_id": job_id, "image": image, "source_path": source_path, "timeout": timeout},
        daemon=True,
        name=f"secureshield-job-{job_id}",
    )
    worker.start()


def _run_full_scan_job(job_id: int, *, image: str, source_path: str | None, timeout: int) -> None:
    scanner = SecureShieldScanner(timeout=timeout)
    job = get_scan_job(job_id)
    owner = get_user(job["requested_by"]) if job and job.get("requested_by") else None
    update_scan_job(job_id, status="running", progress=10, metadata_updates={"image": image, "source_path": source_path})

    phase_progress = {
        "scan_started": 12,
        "module_started": {"cve": 20, "cis": 40, "supply_chain": 58, "runtime": 76, "secrets": 88},
        "module_completed": {"cve": 32, "cis": 52, "supply_chain": 70, "runtime": 84, "secrets": 95},
        "scan_completed": 100,
    }

    def on_progress(event: dict[str, Any]) -> None:
        phase = event.get("phase")
        module = event.get("module")
        progress = None
        if phase == "module_started":
            progress = phase_progress["module_started"].get(module, 15)
        elif phase == "module_completed":
            progress = phase_progress["module_completed"].get(module, 90)
        elif phase in {"scan_started", "scan_completed"}:
            progress = phase_progress[phase]
        if progress is not None:
            update_scan_job(job_id, progress=progress, metadata_updates={"last_event": event})

    try:
        result = scanner.scan_with_progress(image, source_path=source_path, progress_callback=on_progress)
        saved = save_scan_result(
            scan_type="full",
            target=image,
            source_path=result.get("source_path"),
            result=result,
            owner=owner,
        )
        cache_store.set(
            f"latest_scan:{image}",
            {"record_id": saved["id"], "summary": result.get("summary"), "security_score": result.get("security_score")},
            ttl_seconds=900,
        )
        update_scan_job(
            job_id,
            status="completed",
            progress=100,
            result_record_id=saved["id"],
            metadata_updates={"summary": result.get("summary"), "security_score": result.get("security_score")},
        )
    except ScannerError as exc:
        update_scan_job(job_id, status="failed", progress=100, error=str(exc))
    except Exception as exc:  # pragma: no cover
        update_scan_job(job_id, status="failed", progress=100, error=f"Unexpected job error: {exc}")
