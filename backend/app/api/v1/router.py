"""
Merged API v1 router — combines user's routes + V2 production routes.
All under /api/v1/
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/v1")

# ── Auth ──────────────────────────────────────────────────────────────────────
from app.api.v1.auth.routes import router as auth_router
router.include_router(auth_router)               # /api/v1/auth/*

# ── Assets (legacy) ───────────────────────────────────────────────────────────
from app.api.v1.assets.routes import router as assets_router
router.include_router(assets_router)             # /api/v1/assets/*

# ── Scans (legacy) ────────────────────────────────────────────────────────────
from app.api.v1.scans.routes import router as scans_router
router.include_router(scans_router)              # /api/v1/scans/*

# ── Dashboard ─────────────────────────────────────────────────────────────────
from app.api.v1.dashboard.routes import router as dashboard_router
router.include_router(dashboard_router)          # /api/v1/dashboard/*

# ── Attack Surface (user's new routes) ────────────────────────────────────────
from app.api.v1.attack_surface import router as attack_surface_router
router.include_router(attack_surface_router)     # /api/v1/attack-surface/*

# ── Super Admin & Organization ────────────────────────────────────────────────
from app.api.v1.super_admin import super_admin_router, organization_router
router.include_router(super_admin_router)        # /api/v1/super-admin/*
router.include_router(organization_router)       # /api/v1/organization/*

# ── AI Analysis ───────────────────────────────────────────────────────────────
from app.api.v1.ai_analysis import router as ai_analysis_router
router.include_router(ai_analysis_router)        # /api/v1/ai/*

# ── Phases 2-10 (vulnerabilities, TI, alerts, reports, etc.) ─────────────────
from app.api.v1.phases_2_to_10 import (
    ports_router, vuln_router, ti_router, secrets_router,
    alerts_router, ai_router, enterprise_router, reports_router, backup_router
)
router.include_router(ports_router)
router.include_router(vuln_router)
router.include_router(ti_router)
router.include_router(secrets_router)
router.include_router(alerts_router)
router.include_router(ai_router)
router.include_router(enterprise_router)
router.include_router(reports_router)
router.include_router(backup_router)

# ── V2 Production Routes ──────────────────────────────────────────────────────
# ASM production (assets/scans/schedules/vulns/reports) under /api/v1/asm/*
from app.api.v1.asm_routes import router as asm_router
router.include_router(asm_router)                # /api/v1/asm/*

# Recon engine under /api/v1/recon/*
from app.api.v1.recon.routes import router as recon_v2_router
router.include_router(recon_v2_router)           # /api/v1/recon/*

# AI Pentest under /api/v1/pentest/*
from app.api.v1.pentest.routes import router as pentest_router
router.include_router(pentest_router)            # /api/v1/pentest/*

# ── Schedules (alias from user api.js calls /api/v1/schedules/*) ─────────────
# Route these to the ASM schedules endpoint
from fastapi import APIRouter as _AR, Depends
from app.dependencies import get_current_user
from app.utils.database import get_db
from sqlalchemy.orm import Session

_sched = _AR(prefix="/schedules", tags=["schedules"])

@_sched.get("")
async def list_schedules_alias(current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import list_schedules
    return await list_schedules(None, current_user, db)

@_sched.post("")
async def create_schedule_alias(body: dict, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import ScheduleCreate, create_schedule
    return await create_schedule(ScheduleCreate(**body), current_user, db)

@_sched.put("/{schedule_id}/toggle")
async def toggle_schedule_alias(schedule_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import toggle_schedule
    return await toggle_schedule(schedule_id, current_user, db)

@_sched.put("/{schedule_id}/pause")
async def pause_schedule_alias(schedule_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import pause_resume_schedule
    return await pause_resume_schedule(schedule_id, current_user, db)

@_sched.delete("/{schedule_id}", status_code=204)
async def delete_schedule_alias(schedule_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import delete_schedule
    return await delete_schedule(schedule_id, current_user, db)

class PreviewScheduleRequest(BaseModel):
    cron_expression: str
    timezone: Optional[str] = "UTC"

@_sched.post("/preview")
async def preview_schedule_endpoint(body: PreviewScheduleRequest):
    from croniter import croniter
    from datetime import datetime
    import pytz
    from fastapi import HTTPException
    try:
        try:
            tz = pytz.timezone(body.timezone) if body.timezone else pytz.UTC
        except Exception:
            tz = pytz.UTC
            
        now = datetime.now(tz)
        iter = croniter(body.cron_expression, now)
        next_run = iter.get_next(datetime)
        return {
            "next_run_at": next_run.isoformat(),
            "timezone": body.timezone or "UTC"
        }
    except Exception as e:
        raise HTTPException(422, detail=f"Invalid cron expression: {str(e)}")

router.include_router(_sched)

# ── Vulnerabilities alias (/api/v1/vulnerabilities/* → /api/v1/asm/vulnerabilities/*) ──
_vuln_alias = _AR(prefix="/vulnerabilities", tags=["vulnerabilities"])

@_vuln_alias.get("")
async def list_vulns_alias(current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import list_vulnerabilities
    return await list_vulnerabilities(None, None, None, None, 0, 100, current_user, db)

@_vuln_alias.get("/{vuln_id}")
async def get_vuln_alias(vuln_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import get_vulnerability
    return await get_vulnerability(vuln_id, current_user, db)

@_vuln_alias.post("/{vuln_id}/false-positive")
async def fp_alias(vuln_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import mark_false_positive
    return await mark_false_positive(vuln_id, current_user, db)

router.include_router(_vuln_alias)

# ── Reports alias (/api/v1/reports/* → /api/v1/asm/reports/*) ────────────────
_rep_alias = _AR(prefix="/reports", tags=["reports"])

@_rep_alias.get("")
async def list_reports_alias(current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import list_reports
    return await list_reports(None, current_user, db)

@_rep_alias.get("/{report_id}")
async def get_report_alias(report_id: str, current_user=Depends(get_current_user), db: Session=Depends(get_db)):
    from app.api.v1.asm_routes import get_report
    return await get_report(report_id, current_user, db)

router.include_router(_rep_alias)

__all__ = ["router"]
