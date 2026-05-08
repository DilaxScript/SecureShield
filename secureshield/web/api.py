"""FastAPI application for SecureShield."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from secureshield import __version__
from secureshield.ai import AIConfigError, AIServiceError, GeminiRemediationService
from secureshield.auth import decode_token, hash_password, issue_token, verify_password
from secureshield.cache import cache_store
from secureshield.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, SCAN_ALLOWED_ROOTS
from secureshield.db import database_health, init_database
from secureshield.jobs import start_full_scan_job
from secureshield.reports import export_report_csv, export_report_json, export_report_markdown, get_report_payload
from secureshield.repository import (
    create_scan_job,
    create_user,
    find_latest_scan_record,
    get_scan_job,
    get_scan_record,
    get_user,
    get_user_by_username,
    list_users,
    list_scan_history,
    list_scan_jobs,
    list_report_artifacts,
    save_ai_recommendation,
    save_scan_result,
    update_user_admin,
    update_user_password,
    update_user_profile,
    delete_user,
)
from secureshield.scanner import ScannerError, SecureShieldScanner
from secureshield.scanner.cve import CVEScanner

app = FastAPI(
    title="SecureShield API",
    version=__version__,
    description="Container vulnerability scanning API powered by Trivy.",
)

logger = logging.getLogger(__name__)

scanner = CVEScanner()
ai_service = GeminiRemediationService()
STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"
ASSETS_DIR = STATIC_DIR / "assets"
FAVICON_FILE = STATIC_DIR / "favicon.ico"
FAVICON_PNG_FILE = STATIC_DIR / "favicon.png"
ALLOWED_SOURCE_ROOTS = [Path(value).expanduser().resolve() for value in SCAN_ALLOWED_ROOTS.split(":") if value.strip()]

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")


@app.on_event("startup")
async def startup_event() -> None:
    # Tanglish: app start aagumbodhe table create panna idhu help ஆகும்.
    try:
        init_database()
    except Exception as exc:
        # DB unavailable இருந்தாலும் frontend/API skeleton boot ஆகணும்.
        logger.warning("Database initialization failed during startup: %s", exc)
    try:
        if DEFAULT_ADMIN_PASSWORD and not get_user_by_username(DEFAULT_ADMIN_USERNAME):
            create_user(
                username=DEFAULT_ADMIN_USERNAME,
                password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
                role="admin",
            )
    except Exception as exc:
        logger.warning("Unable to bootstrap default admin user: %s", exc)


@app.get("/", response_model=None)
async def root() -> Response:
    # Tanglish: React build copy pannala na kuda basic landing page work ஆகணும்.
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)

    return JSONResponse(
        {
            "name": "SecureShield",
            "version": __version__,
            "message": "Frontend build not found. Copy your React build into secureshield/web/static/.",
        }
    )


@app.get("/favicon.ico", response_model=None)
async def favicon() -> Response:
    if FAVICON_FILE.exists():
        return FileResponse(FAVICON_FILE, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="Favicon not found.")


@app.get("/favicon.png", response_model=None)
async def favicon_png() -> Response:
    if FAVICON_PNG_FILE.exists():
        return FileResponse(FAVICON_PNG_FILE, media_type="image/png")
    raise HTTPException(status_code=404, detail="Favicon not found.")


@app.get("/api/health")
async def health() -> dict[str, str]:
    try:
        db = database_health()
        database_status = db["status"]
    except Exception:
        database_status = "error"
    cve_scanner = CVEScanner()
    return {
        "status": "ok",
        "service": "secureshield",
        "version": __version__,
        "database": database_status,
        "cache_backend": cache_store.info()["backend"],
        "trivy_cache_dir": cve_scanner.cache_dir or "default",
        "trivy_image_src": cve_scanner.image_src or "default",
        "trivy_offline_scan": str(cve_scanner.offline_scan).lower(),
        "trivy_skip_db_update": str(cve_scanner.skip_db_update).lower(),
        "trivy_timeout_seconds": str(cve_scanner.timeout),
    }


def _parse_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


async def optional_user(authorization: str | None = Header(default=None)) -> dict | None:
    token = _parse_bearer_token(authorization)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except ValueError:
        return None
    user = get_user(int(payload["sub"]))
    if not user or not user.get("is_active", True):
        return None
    return user


async def require_user(user: dict | None = Depends(optional_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


async def require_admin(user: dict = Depends(require_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


def _is_admin(user: dict | None) -> bool:
    return bool(user and user.get("role") == "admin")


def _validate_source_path(path_value: str | None) -> str | None:
    if not path_value:
        return None
    resolved = Path(path_value).expanduser().resolve()
    if not resolved.exists():
        raise HTTPException(status_code=400, detail=f"Source path does not exist: {path_value}")
    if not any(resolved == root or root in resolved.parents for root in ALLOWED_SOURCE_ROOTS):
        allowed = ", ".join(str(root) for root in ALLOWED_SOURCE_ROOTS) or "no configured roots"
        raise HTTPException(status_code=400, detail=f"Source path must be under: {allowed}")
    return str(resolved)


@app.get("/api/scan/{image:path}")
async def scan_image(image: str, source_path: str | None = Query(default=None), user: dict | None = Depends(optional_user)) -> dict:
    if source_path and not user:
        raise HTTPException(status_code=401, detail="Authentication required for filesystem source scans.")
    source_path = _validate_source_path(source_path)
    try:
        existing_record = (
            find_latest_scan_record(scan_type="full", target=image, owner_id=user["id"] if user else None)
            if not source_path
            else None
        )
        if existing_record:
            existing_result = dict(existing_record.get("result") or {})
            existing_result["saved_record"] = {
                key: value for key, value in existing_record.items() if key != "result"
            }
            existing_result["duplicate"] = True
            existing_result["message"] = "This image was already scanned."
            return existing_result

        result = SecureShieldScanner().scan(image, source_path=source_path)
        saved = save_scan_result(
            scan_type="full",
            target=image,
            source_path=result.get("source_path"),
            result=result,
            owner=user,
        )
        result["saved_record"] = saved
        result["duplicate"] = False
        return result
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Unexpected scan error: {exc}") from exc


@app.get("/api/critical/{image:path}")
async def scan_critical(image: str) -> dict:
    try:
        findings = scanner.get_critical_cves(image)
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Unexpected scan error: {exc}") from exc

    return {
        "image": image,
        "critical_count": len(findings),
        "findings": findings,
    }


@app.get("/api/cis/{image:path}")
async def scan_cis(image: str, user: dict | None = Depends(optional_user)) -> dict:
    try:
        result = SecureShieldScanner().scan_cis(image)
        result["saved_record"] = save_scan_result(scan_type="cis", target=image, result=result, owner=user)
        return result
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/runtime/{target:path}")
async def scan_runtime(target: str, user: dict | None = Depends(optional_user)) -> dict:
    try:
        result = SecureShieldScanner().scan_runtime(target)
        result["saved_record"] = save_scan_result(scan_type="runtime", target=target, result=result, owner=user)
        return result
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/supply-chain/{image:path}")
async def scan_supply_chain(image: str, user: dict | None = Depends(optional_user)) -> dict:
    try:
        result = SecureShieldScanner().scan_supply_chain(image)
        result["saved_record"] = save_scan_result(scan_type="supply_chain", target=image, result=result, owner=user)
        return result
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/secrets")
async def scan_secrets(
    path: str = Query(..., description="Filesystem path to scan for embedded secrets"),
    user: dict = Depends(require_user),
) -> dict:
    path = _validate_source_path(path) or path
    try:
        result = SecureShieldScanner().scan_secrets(path)
        result["saved_record"] = save_scan_result(
            scan_type="secrets",
            target=path,
            source_path=path,
            result=result,
            owner=user,
        )
        return result
    except ScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/history")
async def history(
    limit: int = Query(10, ge=1, le=100),
    scan_type: str | None = Query(None, description="Optional scan type filter"),
    user: dict | None = Depends(optional_user),
) -> dict:
    try:
        records = list_scan_history(
            limit=limit,
            scan_type=scan_type,
            owner_id=user["id"] if user else None,
            all_owners=_is_admin(user),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to load scan history: {exc}") from exc
    return {"count": len(records), "records": records}


@app.get("/api/history/{record_id}")
async def history_detail(record_id: int, user: dict | None = Depends(optional_user)) -> dict:
    try:
        record = get_scan_record(record_id, owner_id=user["id"] if user else None, all_owners=_is_admin(user))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to load scan record: {exc}") from exc
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record


@app.get("/api/reports/summary")
async def report_summary(
    limit: int = Query(50, ge=1, le=500),
    scan_type: str | None = Query(None, description="Optional scan type filter"),
    user: dict | None = Depends(optional_user),
) -> dict:
    try:
        return get_report_payload(
            limit=limit,
            scan_type=scan_type,
            owner_id=user["id"] if user else None,
            all_owners=_is_admin(user),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to build report summary: {exc}") from exc


@app.get("/api/reports/export")
async def report_export(
    format: str = Query("json", pattern="^(json|csv|md)$"),
    limit: int = Query(50, ge=1, le=500),
    scan_type: str | None = Query(None, description="Optional scan type filter"),
    user: dict | None = Depends(optional_user),
) -> Response:
    try:
        if format == "csv":
            payload = export_report_csv(
                limit=limit,
                scan_type=scan_type,
                owner_id=user["id"] if user else None,
                all_owners=_is_admin(user),
            )
            return Response(
                content=payload,
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="secureshield-report.csv"'},
            )
        if format == "md":
            payload = export_report_markdown(
                limit=limit,
                scan_type=scan_type,
                owner_id=user["id"] if user else None,
                all_owners=_is_admin(user),
            )
            return Response(
                content=payload,
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="secureshield-report.md"'},
            )

        payload = export_report_json(
            limit=limit,
            scan_type=scan_type,
            owner_id=user["id"] if user else None,
            all_owners=_is_admin(user),
        )
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="secureshield-report.json"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to export report: {exc}") from exc


@app.get("/api/reports/archive")
async def report_archive(limit: int = Query(20, ge=1, le=200), _: dict = Depends(require_admin)) -> dict:
    try:
        items = list_report_artifacts(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to load report archive: {exc}") from exc
    return {"count": len(items), "reports": items}


@app.post("/api/auth/register")
async def register(request: Request) -> dict:
    username, password = await _parse_auth_request(request)
    username = username.strip()
    if len(username) < 3 or len(password) < 8:
        raise HTTPException(status_code=400, detail="Username or password does not meet minimum length.")
    try:
        user = create_user(username=username, password_hash=hash_password(password))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    token = issue_token(user)
    return {"user": user, "token": token}


@app.post("/api/auth/login")
async def login(request: Request) -> dict:
    username, password = await _parse_auth_request(request)
    user = get_user_by_username(username.strip())
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="This account is deactivated.")
    public_user = {key: value for key, value in user.items() if key != "password_hash"}
    token = issue_token(public_user)
    return {"user": public_user, "token": token}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(require_user)) -> dict:
    return {"user": user}


@app.put("/api/auth/profile")
async def update_profile(payload: ProfileUpdateRequest, user: dict = Depends(require_user)) -> dict:
    full_name = payload.full_name.strip() if payload.full_name else ""
    email = payload.email.strip() if payload.email else ""
    job_title = payload.job_title.strip() if payload.job_title else ""
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    updated = update_user_profile(
        user["id"],
        full_name=full_name[:120],
        email=email[:255],
        job_title=job_title[:120],
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user": updated, "token": issue_token(updated)}


@app.put("/api/auth/password")
async def update_password(payload: PasswordUpdateRequest, user: dict = Depends(require_user)) -> dict:
    stored_user = get_user_by_username(user["username"])
    if not stored_user or not verify_password(payload.current_password, stored_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters.")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password.")
    updated = update_user_password(user["id"], password_hash=hash_password(payload.new_password))
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user": updated, "token": issue_token(updated)}


@app.get("/api/admin/users")
async def admin_users(_: dict = Depends(require_admin)) -> dict:
    users = list_users()
    return {"count": len(users), "users": users}


@app.post("/api/admin/users")
async def admin_create_user(payload: AdminCreateUserRequest, _: dict = Depends(require_admin)) -> dict:
    username = payload.username.strip()
    password = payload.password
    role = _normalize_role(payload.role)
    email = payload.email.strip() if payload.email else ""
    if len(username) < 3 or len(password) < 8:
        raise HTTPException(status_code=400, detail="Username or password does not meet minimum length.")
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    try:
        user = create_user(
            username=username,
            password_hash=hash_password(password),
            role=role,
            full_name=(payload.full_name or "").strip()[:120],
            email=email[:255],
            job_title=(payload.job_title or "").strip()[:120],
            is_active=payload.is_active,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"user": user}


@app.put("/api/admin/users/{user_id}")
async def admin_update_user(user_id: int, payload: AdminUpdateUserRequest, admin: dict = Depends(require_admin)) -> dict:
    role = _normalize_role(payload.role) if payload.role is not None else None
    email = payload.email.strip() if payload.email else ""
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if user_id == admin["id"] and payload.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own admin account.")
    updated = update_user_admin(
        user_id,
        role=role,
        full_name=(payload.full_name or "").strip()[:120] if payload.full_name is not None else None,
        email=email[:255] if payload.email is not None else None,
        job_title=(payload.job_title or "").strip()[:120] if payload.job_title is not None else None,
        is_active=payload.is_active,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user": updated}


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: int, admin: dict = Depends(require_admin)) -> dict:
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own admin account.")
    deleted = delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"deleted": True}


@app.post("/api/jobs/scan")
async def create_full_scan_job(payload: ScanJobRequest, user: dict = Depends(require_user)) -> dict:
    image = payload.image.strip()
    if not image:
        raise HTTPException(status_code=400, detail="Image is required.")
    source_path = _validate_source_path(payload.source_path)
    job = create_scan_job(
        scan_type="full",
        target=image,
        source_path=source_path,
        requested_by=user["id"] if user else None,
        metadata={"requested_via": "api"},
    )
    start_full_scan_job(job["id"], image=image, source_path=source_path, timeout=payload.timeout)
    return {"job": job}


@app.get("/api/jobs")
async def scan_jobs(limit: int = Query(20, ge=1, le=200), user: dict = Depends(require_user)) -> dict:
    items = list_scan_jobs(limit=limit)
    if user and not _is_admin(user):
        items = [item for item in items if item.get("requested_by") == user["id"]]
    return {"count": len(items), "jobs": items}


@app.get("/api/jobs/{job_id}")
async def scan_job_detail(job_id: int, user: dict = Depends(require_user)) -> dict:
    item = get_scan_job(job_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    if not _is_admin(user) and item.get("requested_by") != user["id"]:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return item


class AIRemediationRequest(BaseModel):
    image: str | None = None
    finding: dict


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileUpdateRequest(BaseModel):
    full_name: str = ""
    email: str = ""
    job_title: str = ""


class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str


class AdminCreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    full_name: str = ""
    email: str = ""
    job_title: str = ""
    is_active: bool = True


class AdminUpdateUserRequest(BaseModel):
    role: str | None = None
    full_name: str | None = None
    email: str | None = None
    job_title: str | None = None
    is_active: bool | None = None


def _normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in {"admin", "analyst"}:
        raise HTTPException(status_code=400, detail="Role must be admin or analyst.")
    return normalized


async def _parse_auth_request(request: Request) -> tuple[str, str]:
    content_type = (request.headers.get("content-type") or "").lower()

    if "application/json" in content_type:
        payload = await request.json()
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
    else:
        raw_body = (await request.body()).decode("utf-8", errors="ignore")
        form = parse_qs(raw_body)
        username = str((form.get("username") or [""])[0] or "")
        password = str((form.get("password") or [""])[0] or "")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    return username, password


class ScanJobRequest(BaseModel):
    image: str
    source_path: str | None = None
    timeout: int = 300


class AIChatRequest(BaseModel):
    image: str | None = None
    finding: dict
    question: str
    history: list[dict[str, str]] = Field(default_factory=list)


@app.post("/api/ai/remediate")
async def ai_remediate(payload: AIRemediationRequest) -> dict:
    try:
        guidance = ai_service.remediate(payload.finding, image=payload.image)
    except AIConfigError as exc:
        guidance = _ai_disabled_response(str(exc))
    except AIServiceError as exc:
        logger.warning("AI remediation service error for finding %s: %s", payload.finding.get("id"), exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    saved = save_ai_recommendation(
        interaction_type="remediation",
        finding_id=payload.finding.get("id") or payload.finding.get("cve_id"),
        image_name=payload.image,
        prompt=None,
        response=guidance,
    )
    return {
        "image": payload.image,
        "finding_id": payload.finding.get("id") or payload.finding.get("cve_id"),
        "guidance": guidance,
        "saved_recommendation": saved,
    }


@app.post("/api/ai/chat")
async def ai_chat(payload: AIChatRequest) -> dict:
    try:
        response = ai_service.chat(
            finding=payload.finding,
            question=payload.question,
            image=payload.image,
            history=payload.history,
        )
    except AIConfigError as exc:
        response = _ai_disabled_response(str(exc))
    except AIServiceError as exc:
        logger.warning("AI chat service error for finding %s: %s", payload.finding.get("id"), exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    saved = save_ai_recommendation(
        interaction_type="chat",
        finding_id=payload.finding.get("id") or payload.finding.get("cve_id"),
        image_name=payload.image,
        prompt=payload.question,
        response=response,
    )
    return {
        "image": payload.image,
        "finding_id": payload.finding.get("id") or payload.finding.get("cve_id"),
        "response": response,
        "saved_recommendation": saved,
    }


def _ai_disabled_response(detail: str) -> dict[str, Any]:
    return {
        "answer": "AI assistance is disabled because GEMINI_API_KEY is not configured.",
        "summary": "AI assistance is disabled.",
        "risk": "No AI analysis was generated.",
        "remediation_steps": [
            "Set GEMINI_API_KEY in .env to enable AI remediation and chat.",
            "Restart SecureShield after updating the environment.",
        ],
        "safe_example": "GEMINI_API_KEY=your-api-key",
        "priority": "info",
        "disclaimer": detail,
    }


@app.websocket("/ws/scan")
async def scan_progress_socket(websocket: WebSocket) -> None:
    await websocket.accept()

    try:
        token = websocket.query_params.get("token")
        socket_user: dict | None = None
        if token:
            try:
                payload = decode_token(token)
                socket_user = get_user(int(payload["sub"]))
            except ValueError:
                socket_user = None

        while True:
            payload = await websocket.receive_json()
            image = str(payload.get("image") or "").strip()
            source_path = payload.get("source_path")
            if not image:
                await websocket.send_json({"event": "error", "detail": "Missing image value."})
                continue
            if source_path and not socket_user:
                await websocket.send_json({"event": "error", "detail": "Authentication required for filesystem source scans."})
                continue
            try:
                source_path = _validate_source_path(str(source_path)) if source_path else None
            except HTTPException as exc:
                await websocket.send_json({"event": "error", "detail": exc.detail})
                continue

            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[dict] = asyncio.Queue()

            def progress_callback(event: dict) -> None:
                loop.call_soon_threadsafe(queue.put_nowait, {"event": "progress", **event})

            async def producer() -> dict:
                result = await asyncio.to_thread(
                    SecureShieldScanner().scan_with_progress,
                    image,
                    source_path,
                    progress_callback,
                )
                saved = save_scan_result(
                    scan_type="full",
                    target=image,
                    source_path=result.get("source_path"),
                    result=result,
                    owner=socket_user,
                )
                result["saved_record"] = saved
                result["duplicate"] = False
                return result

            task = asyncio.create_task(producer())

            while not task.done() or not queue.empty():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.2)
                    await websocket.send_json(event)
                except TimeoutError:
                    continue

            try:
                result = await task
            except ScannerError as exc:
                await websocket.send_json({"event": "error", "detail": str(exc)})
                continue
            except Exception as exc:  # pragma: no cover
                await websocket.send_json({"event": "error", "detail": f"Unexpected scan error: {exc}"})
                continue

            await websocket.send_json({"event": "result", "data": result})
    except WebSocketDisconnect:
        return


@app.get("/{full_path:path}", response_model=None)
async def spa_fallback(full_path: str) -> Response:
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found.")
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)
    return JSONResponse(
        {
            "name": "SecureShield",
            "version": __version__,
            "message": "Frontend build not found. Copy your React build into secureshield/web/static/.",
        }
    )
