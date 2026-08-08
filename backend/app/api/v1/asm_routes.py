"""
Production ASM API Routes
Assets / Schedules / Scan Jobs / Vulnerabilities / Reports / Logs
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, Response, Request
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.models.scan_models import (
    ASMAsset, ScanSchedule, ScanJob, ToolExecution,
    VulnFinding, ScanReport, ScanLog
)
from app.utils.logger import get_logger
from croniter import croniter
from app.tasks.scan_tasks import _next_run

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/asm", tags=["asm"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name:        str
    target:      str
    asset_type:  str = "domain"
    description: Optional[str] = None
    tags:        List[str] = []

    @validator("target", "name")
    def validate_target_chars(cls, v):
        blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
        for b in blocked:
            if b in v:
                raise ValueError(f"Character '{b}' is not allowed in target/name")
        return v

    @validator("description")
    def sanitize_description(cls, v):
        if v:
            return v.replace("<", "").replace(">", "")
        return v

    @validator("tags", each_item=True)
    def sanitize_tags(cls, v):
        if v:
            return v.replace("<", "").replace(">", "")
        return v


class ScheduleCreate(BaseModel):
    asset_id:        str
    cron_expression: str = "0 2 * * *"
    is_enabled:      bool = True
    notify_on_completion: bool = False
    notify_email:    Optional[str] = None

    @validator("cron_expression")
    def validate_cron(cls, v):
        try:
            croniter(v)
        except Exception:
            raise ValueError("Invalid cron expression")
        return v


class ScanTrigger(BaseModel):
    asset_id: str


# ── Assets ────────────────────────────────────────────────────────────────────

@router.get("/assets")
async def list_assets(
    request: Request,
    search: Optional[str] = None,
    asset_type: Optional[str] = None,
    skip: int = 0, limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(ASMAsset)
    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    if search:
        q = q.filter(ASMAsset.target.ilike(f"%{search}%") | ASMAsset.name.ilike(f"%{search}%"))
    if asset_type:
        q = q.filter(ASMAsset.asset_type == asset_type)
    total = q.count()
    assets = q.offset(skip).limit(limit).all()
    return {
        "total": total,
        "assets": [_asset_dict(a, db) for a in assets],
    }


@router.post("/assets", status_code=201)
async def create_asset(
    request: Request,
    body: AssetCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    asset = ASMAsset(
        user_id=current_user.id,
        tenant_id=org_id,
        name=body.name,
        target=body.target.strip().lower(),
        asset_type=body.asset_type,
        description=body.description,
        tags=body.tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_dict(asset, db)


@router.put("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetCreate,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    asset = _get_asset(db, asset_id, current_user.id, tenant_id=org_id)
    asset.name = body.name
    asset.target = body.target.strip().lower()
    asset.asset_type = body.asset_type
    asset.description = body.description
    asset.tags = body.tags
    db.commit()
    return _asset_dict(asset, db)


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    asset = _get_asset(db, asset_id, current_user.id, tenant_id=org_id)
    db.delete(asset)
    db.commit()


# ── Schedules ─────────────────────────────────────────────────────────────────

@router.get("/schedules")
async def list_schedules(
    request: Request,
    asset_id: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(ScanSchedule).join(ASMAsset)
    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    if asset_id:
        q = q.filter(ScanSchedule.asset_id == asset_id)
    schedules = q.all()
    return {"schedules": [_schedule_dict(s) for s in schedules]}


@router.post("/schedules", status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    _get_asset(db, body.asset_id, current_user.id, tenant_id=org_id)
    sched = ScanSchedule(
        asset_id=body.asset_id,
        cron_expression=body.cron_expression,
        is_enabled=body.is_enabled,
        next_run_at=_next_run(body.cron_expression),
        notify_on_completion=body.notify_on_completion,
        notify_email=body.notify_email,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return _schedule_dict(sched)


@router.put("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    sched = _get_schedule(db, schedule_id, current_user.id, tenant_id=org_id)
    sched.is_enabled = not sched.is_enabled
    db.commit()
    return {"is_enabled": sched.is_enabled}


@router.put("/schedules/{schedule_id}/pause")
async def pause_resume_schedule(
    schedule_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    sched = _get_schedule(db, schedule_id, current_user.id, tenant_id=org_id)
    sched.is_paused = not sched.is_paused
    db.commit()
    return {"is_paused": sched.is_paused}


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    sched = _get_schedule(db, schedule_id, current_user.id, tenant_id=org_id)
    db.delete(sched)
    db.commit()


# ── Scan Jobs ─────────────────────────────────────────────────────────────────

@router.post("/scans/trigger", status_code=202)
async def trigger_scan(
    body: ScanTrigger,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manually trigger a scan for an asset. Works with or without Celery."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id
    asset = _get_asset(db, body.asset_id, current_user.id, tenant_id=org_id)

    # Prevent duplicate running scans
    running = (
        db.query(ScanJob)
        .filter(ScanJob.asset_id == asset.id, ScanJob.status.in_(["queued", "running"]))
        .first()
    )
    if running:
        raise HTTPException(409, f"Scan already {running.status} for this asset")

    job = ScanJob(asset_id=asset.id, triggered_by="manual", status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)

    # Try Celery first; fall back to in-process FastAPI BackgroundTasks
    try:
        from app.tasks.scan_tasks import run_scan_job
        run_scan_job.delay(job.id)
        mode = "celery"
    except Exception:
        background_tasks.add_task(_run_scan_background, job.id)
        mode = "background"

    return {"scan_job_id": job.id, "status": "queued",
            "message": f"Scan queued ({mode})"}


@router.get("/scans")
async def list_scans(
    request: Request,
    asset_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 20,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(ScanJob).join(ASMAsset)
    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    if asset_id:
        q = q.filter(ScanJob.asset_id == asset_id)
    if status:
        q = q.filter(ScanJob.status == status)
    jobs = q.order_by(ScanJob.created_at.desc()).limit(limit).all()
    return {"scans": [_job_dict(j) for j in jobs]}


@router.get("/scans/{scan_job_id}")
async def get_scan(
    scan_job_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    if org_id:
        if job.asset.tenant_id != org_id:
            raise HTTPException(404, "Scan not found")
    elif job.asset.user_id != current_user.id:
        raise HTTPException(404, "Scan not found")
    return _job_dict(job, detail=True)


@router.get("/scans/{scan_job_id}/tools")
async def get_tool_executions(
    scan_job_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    if org_id:
        if job.asset.tenant_id != org_id:
            raise HTTPException(404, "Scan not found")
    elif job.asset.user_id != current_user.id:
        raise HTTPException(404, "Scan not found")
    tools = (
        db.query(ToolExecution)
        .filter(ToolExecution.scan_job_id == scan_job_id)
        .order_by(ToolExecution.order_index)
        .all()
    )
    return {"tools": [_tool_dict(t) for t in tools]}


@router.get("/scans/{scan_job_id}/logs")
async def get_scan_logs(
    scan_job_id: str,
    request: Request,
    since_id: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    if org_id:
        if job.asset.tenant_id != org_id:
            raise HTTPException(404, "Scan not found")
    elif job.asset.user_id != current_user.id:
        raise HTTPException(404, "Scan not found")
    q = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_job_id)
    if since_id:
        q = q.filter(ScanLog.id > since_id)
    logs = q.order_by(ScanLog.logged_at).limit(500).all()
    return {"logs": [{"id": l.id, "level": l.level, "message": l.message, "tool": l.tool, "logged_at": l.logged_at.isoformat() if l.logged_at else ""} for l in logs]}


@router.post("/scans/{scan_job_id}/cancel")
async def cancel_scan(
    scan_job_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    if org_id:
        if job.asset.tenant_id != org_id:
            raise HTTPException(404, "Scan not found")
    elif job.asset.user_id != current_user.id:
        raise HTTPException(404, "Scan not found")
    from app.tasks.scan_tasks import cancel_scan_job
    cancel_scan_job.delay(scan_job_id)
    return {"message": "Cancellation requested"}


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@router.get("/vulnerabilities")
async def list_vulnerabilities(
    request: Request,
    asset_id: Optional[str] = None,
    scan_job_id: Optional[str] = None,
    severity: Optional[str] = None,
    source_tool: Optional[str] = None,
    skip: int = 0, limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = (db.query(VulnFinding)
         .join(ScanJob)
         .join(ASMAsset)
         .filter(VulnFinding.is_duplicate == False))

    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    if asset_id:      q = q.filter(VulnFinding.asset_id == asset_id)
    if scan_job_id:   q = q.filter(VulnFinding.scan_job_id == scan_job_id)
    if severity:      q = q.filter(VulnFinding.severity == severity.lower())
    if source_tool:   q = q.filter(VulnFinding.source_tool == source_tool)

    total = q.count()
    vulns = q.order_by(VulnFinding.created_at.desc()).offset(skip).limit(limit).all()
    return {"total": total, "vulnerabilities": [_vuln_dict(v) for v in vulns]}


@router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability(
    vuln_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    v = db.get(VulnFinding, vuln_id)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    if org_id:
        if v.scan_job.asset.tenant_id != org_id:
            raise HTTPException(404, "Vulnerability not found")
    elif v.scan_job.asset.user_id != current_user.id:
        raise HTTPException(404, "Vulnerability not found")
    return _vuln_dict(v, detail=True)


@router.post("/vulnerabilities/{vuln_id}/false-positive")
async def mark_false_positive(
    vuln_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    v = db.get(VulnFinding, vuln_id)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    if org_id:
        if v.scan_job.asset.tenant_id != org_id:
            raise HTTPException(404, "Vulnerability not found")
    elif v.scan_job.asset.user_id != current_user.id:
        raise HTTPException(404, "Vulnerability not found")
    v.is_false_positive = not v.is_false_positive
    db.commit()
    return {"is_false_positive": v.is_false_positive}


# ── Reports ───────────────────────────────────────────────────────────────────

@router.get("/reports")
async def list_reports(
    request: Request,
    asset_id: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = (db.query(ScanReport)
         .join(ScanJob)
         .join(ASMAsset))

    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    if asset_id:
        q = q.filter(ScanReport.asset_id == asset_id)
    reports = q.order_by(ScanReport.created_at.desc()).limit(50).all()
    return {"reports": [_report_dict(r) for r in reports]}


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    r = db.get(ScanReport, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    if org_id:
        if r.scan_job.asset.tenant_id != org_id:
            raise HTTPException(404, "Report not found")
    elif r.scan_job.asset.user_id != current_user.id:
        raise HTTPException(404, "Report not found")
    return _report_dict(r, detail=True)


@router.get("/reports/{report_id}/export/{fmt}")
async def export_report(
    report_id: str,
    fmt: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    r = db.get(ScanReport, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    if org_id:
        if r.scan_job.asset.tenant_id != org_id:
            raise HTTPException(404, "Report not found")
    elif r.scan_job.asset.user_id != current_user.id:
        raise HTTPException(404, "Report not found")
    if fmt == "markdown":
        return Response(
            content=r.markdown_report or "",
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="report-{r.id[:8]}.md"'}
        )
    if fmt == "json":
        import json
        return Response(
            content=json.dumps(_report_dict(r, detail=True), default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report-{r.id[:8]}.json"'}
        )
    raise HTTPException(400, "Unsupported format. Use: markdown, json")


# ── Dashboard stats ───────────────────────────────────────────────────────────

@router.get("/dashboard")
async def dashboard_stats(
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(ASMAsset)
    if org_id:
        q = q.filter(ASMAsset.tenant_id == org_id)
    else:
        q = q.filter(ASMAsset.user_id == current_user.id)

    asset_ids = [a.id for a in q.all()]
    if not asset_ids:
        return {"assets": 0, "scans": {}, "vulnerabilities": {}, "running_scans": []}

    scans_q = db.query(ScanJob).filter(ScanJob.asset_id.in_(asset_ids))
    scan_counts = {
        "total":     scans_q.count(),
        "running":   scans_q.filter(ScanJob.status == "running").count(),
        "queued":    scans_q.filter(ScanJob.status == "queued").count(),
        "completed": scans_q.filter(ScanJob.status == "completed").count(),
        "failed":    scans_q.filter(ScanJob.status == "failed").count(),
    }

    vuln_q = (db.query(VulnFinding)
              .filter(VulnFinding.asset_id.in_(asset_ids))
              .filter(VulnFinding.is_duplicate == False)
              .filter(VulnFinding.is_false_positive == False))
    vuln_counts = {
        "total":    vuln_q.count(),
        "critical": vuln_q.filter(VulnFinding.severity == "critical").count(),
        "high":     vuln_q.filter(VulnFinding.severity == "high").count(),
        "medium":   vuln_q.filter(VulnFinding.severity == "medium").count(),
        "low":      vuln_q.filter(VulnFinding.severity == "low").count(),
    }

    # Running scans with progress
    running = (
        db.query(ScanJob)
        .filter(ScanJob.asset_id.in_(asset_ids), ScanJob.status.in_(["running","queued"]))
        .all()
    )

    return {
        "assets":      len(asset_ids),
        "scans":       scan_counts,
        "vulnerabilities": vuln_counts,
        "running_scans": [_job_dict(j) for j in running],
    }


# ── Serializers ───────────────────────────────────────────────────────────────

def _asset_dict(a: ASMAsset, db=None) -> dict:
    scan_count = 0
    if db:
        scan_count = db.query(ScanJob).filter(ScanJob.asset_id == a.id).count()
    return {
        "id": a.id, "name": a.name, "target": a.target,
        "asset_type": a.asset_type, "description": a.description,
        "tags": a.tags or [], "is_active": a.is_active,
        "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "scan_count": scan_count,
    }


def _schedule_dict(s: ScanSchedule) -> dict:
    return {
        "id": s.id, "asset_id": s.asset_id,
        "cron_expression": s.cron_expression,
        "is_enabled": s.is_enabled, "is_paused": s.is_paused,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "last_run_status": s.last_run_status,
        "run_count": s.run_count, "fail_count": s.fail_count,
    }


def _job_dict(j: ScanJob, detail: bool = False) -> dict:
    d = {
        "id": j.id, "asset_id": j.asset_id,
        "asset_target": j.asset.target if j.asset else "",
        "asset_name": j.asset.name if j.asset else "",
        "status": j.status, "progress": j.progress,
        "current_tool": j.current_tool,
        "triggered_by": j.triggered_by,
        "started_at":  j.started_at.isoformat() if j.started_at else None,
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        "duration_seconds": j.duration_seconds,
        "error_message": j.error_message,
        "created_at": j.created_at.isoformat() if j.created_at else None,
    }
    if detail:
        d["tool_executions"] = [_tool_dict(t) for t in j.tool_executions]
        d["vuln_count"] = len([v for v in j.vulnerabilities if not v.is_duplicate])
        d["has_report"] = j.scan_report is not None
    return d


def _tool_dict(t: ToolExecution) -> dict:
    return {
        "id": t.id, "tool_name": t.tool_name,
        "order_index": t.order_index, "status": t.status,
        "command": t.command, "exit_code": t.exit_code,
        "started_at": t.started_at.isoformat() if t.started_at else None,
        "finished_at": t.finished_at.isoformat() if t.finished_at else None,
        "duration_seconds": t.duration_seconds,
        "result_count": t.result_count,
        "error_message": t.error_message,
        "raw_output_preview": (t.raw_output or "")[:500],
    }


def _vuln_dict(v: VulnFinding, detail: bool = False) -> dict:
    d = {
        "id": v.id, "title": v.title, "severity": v.severity,
        "cvss_score": v.cvss_score, "cve_id": v.cve_id, "cwe_id": v.cwe_id,
        "host": v.host, "url": v.url, "port": v.port,
        "parameter": v.parameter,
        "source_tool": v.source_tool,
        "is_false_positive": v.is_false_positive,
        "tags": v.tags or [], "references": v.references or [],
        "scan_job_id": v.scan_job_id, "asset_id": v.asset_id,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }
    if detail:
        d.update({
            "description": v.description,
            "impact": v.impact,
            "recommendation": v.recommendation,
            "http_request": v.http_request,
            "http_response": v.http_response,
            "proof_of_concept": v.proof_of_concept,
            "raw_evidence": v.raw_evidence,
            "screenshots": [{"id": s.id, "url": s.url, "file_path": s.file_path}
                            for s in v.screenshots],
        })
    return d


def _report_dict(r: ScanReport, detail: bool = False) -> dict:
    d = {
        "id": r.id, "scan_job_id": r.scan_job_id, "asset_id": r.asset_id,
        "total_vulns": r.total_vulns,
        "critical_count": r.critical_count, "high_count": r.high_count,
        "medium_count": r.medium_count, "low_count": r.low_count,
        "risk_score": r.risk_score, "risk_rating": r.risk_rating,
        "technologies": r.technologies or [],
        "subdomains_found": r.subdomains_found or [],
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
    if detail:
        d.update({
            "executive_summary": r.executive_summary,
            "technical_summary": r.technical_summary,
            "attack_surface": r.attack_surface,
            "open_ports": r.open_ports,
            "recommendations": r.recommendations,
            "markdown_report": r.markdown_report,
        })
    return d


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_asset(db, asset_id, user_id, tenant_id=None):
    a = db.get(ASMAsset, asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
    if tenant_id:
        if a.tenant_id != tenant_id:
            raise HTTPException(404, "Asset not found")
    else:
        if a.user_id != user_id:
            raise HTTPException(404, "Asset not found")
    return a


def _get_schedule(db, schedule_id, user_id, tenant_id=None):
    s = db.get(ScanSchedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    if tenant_id:
        if s.asset.tenant_id != tenant_id:
            raise HTTPException(404, "Schedule not found")
    else:
        if s.asset.user_id != user_id:
            raise HTTPException(404, "Schedule not found")
    return s


async def _run_scan_background(scan_job_id: str):
    """In-process fallback scan runner — used when Celery is not available."""
    from app.utils.database import SessionLocal
    from app.models.scan_models import ScanJob, ASMAsset
    from app.services.scanner_pipeline import ScanPipeline
    from app.services.report_service import ReportService

    db = SessionLocal()
    try:
        job   = db.get(ScanJob, scan_job_id)
        asset = db.get(ASMAsset, job.asset_id)

        job.started_at = datetime.utcnow()
        job.status     = "running"
        db.commit()

        pipeline = ScanPipeline(db, scan_job_id)
        summary  = await pipeline.run(asset)

        await ReportService(db).generate(scan_job_id, summary)

        db.expire_all()
        job              = db.get(ScanJob, scan_job_id)
        job.status       = "completed"
        job.progress     = 100
        job.current_tool = "done"
        job.finished_at  = datetime.utcnow()
        if job.started_at:
            job.duration_seconds = int((job.finished_at - job.started_at).total_seconds())
        db.commit()
    except Exception as e:
        db.rollback()
        job = db.get(ScanJob, scan_job_id)
        if job:
            job.status        = "failed"
            job.error_message = str(e)[:500]
            job.finished_at   = datetime.utcnow()
            db.commit()
    finally:
        db.close()
