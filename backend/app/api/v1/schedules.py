"""Authenticated recurring scan schedule API."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, require_org_admin
from app.models import Asset, ScanSchedule
from app.services.asset_service import AssetService
from app.services.cron_service import (
    CronExpression,
    CronValidationError,
    validate_timezone,
)
from app.services.email_service import EmailConfigurationError, EmailService
from app.utils.database import get_db


router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleCreateRequest(BaseModel):
    asset_id: str
    cron_expression: str = Field(..., min_length=5, max_length=100)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    is_enabled: bool = True
    notify_on_completion: bool = False
    notify_email: EmailStr | None = None
    confirmed_authorized: bool = False


class SchedulePreviewRequest(BaseModel):
    cron_expression: str = Field(..., min_length=5, max_length=100)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)


class TestEmailRequest(BaseModel):
    recipient: EmailStr | None = None


def _owned_schedule(db: Session, organization_id: str, schedule_id: str) -> ScanSchedule:
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.organization_id == organization_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


def _serialize(schedule: ScanSchedule, asset: Asset | None) -> dict:
    return {
        "id": schedule.id,
        "asset_id": schedule.asset_id,
        "asset_name": asset.name if asset else "Deleted asset",
        "target": (asset.target or asset.name) if asset else None,
        "cron_expression": schedule.cron_expression,
        "timezone": schedule.timezone,
        "scan_type": schedule.scan_type,
        "is_enabled": schedule.is_enabled,
        "is_paused": schedule.is_paused,
        "notify_on_completion": schedule.notify_on_completion,
        "notify_email": schedule.notify_email,
        "notification_status": schedule.notification_status,
        "next_run_at": schedule.next_run_at,
        "last_run_at": schedule.last_run_at,
        "last_run_status": schedule.last_run_status,
        "last_scan_id": schedule.last_scan_id,
        "last_error": schedule.last_error,
        "run_count": schedule.run_count or 0,
        "fail_count": schedule.fail_count or 0,
        "created_at": schedule.created_at,
        "updated_at": schedule.updated_at,
    }


@router.get("")
async def list_schedules(
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(ScanSchedule, Asset)
        .outerjoin(Asset, ScanSchedule.asset_id == Asset.id)
        .filter(ScanSchedule.organization_id == current_user.current_organization_id)
        .order_by(ScanSchedule.created_at.desc())
        .all()
    )
    schedules = [_serialize(schedule, asset) for schedule, asset in rows]
    return {"schedules": schedules, "total": len(schedules)}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_schedule(
    request: ScheduleCreateRequest,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    if not request.confirmed_authorized:
        raise HTTPException(
            status_code=400,
            detail="Confirm that you own the target or have written permission to scan it",
        )

    asset = db.query(Asset).filter(
        Asset.id == request.asset_id,
        Asset.organization_id == current_user.current_organization_id,
        Asset.status == "active",
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Active asset not found")
    if not AssetService._domain_from_target(asset.target or asset.name):
        raise HTTPException(
            status_code=422,
            detail="Scheduled scans require an asset with a valid domain or URL target",
        )

    try:
        expression = CronExpression(request.cron_expression)
        validate_timezone(request.timezone)
    except CronValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    notify_email = str(request.notify_email or current_user.email)
    if request.notify_on_completion:
        try:
            EmailService.require_configured()
        except EmailConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    now = datetime.now(timezone.utc)
    schedule = ScanSchedule(
        organization_id=current_user.current_organization_id,
        user_id=current_user.id,
        asset_id=asset.id,
        cron_expression=expression.expression,
        timezone=request.timezone,
        scan_type="scheduled_full",
        is_enabled=request.is_enabled,
        is_paused=False,
        authorization_confirmed_at=now,
        notify_on_completion=request.notify_on_completion,
        notify_email=notify_email if request.notify_on_completion else None,
        notification_status=(
            "ready" if request.notify_on_completion else None
        ),
        next_run_at=(
            expression.next_after(now, request.timezone)
            if request.is_enabled
            else None
        ),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule, asset)


@router.post("/preview")
async def preview_schedule(
    request: SchedulePreviewRequest,
    current_user=Depends(require_org_admin()),
):
    try:
        expression = CronExpression(request.cron_expression)
        zone = validate_timezone(request.timezone)
        next_run = expression.next_after(datetime.now(timezone.utc), request.timezone)
    except CronValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "cron_expression": expression.expression,
        "timezone": request.timezone,
        "next_run_at": next_run,
        "next_run_local": next_run.astimezone(zone).isoformat(),
    }


@router.get("/mail/status")
async def mail_status(current_user=Depends(require_org_admin())):
    return EmailService.configuration_status()


@router.post("/mail/test")
async def send_test_email(
    request: TestEmailRequest,
    current_user=Depends(require_org_admin()),
):
    recipient = str(request.recipient or current_user.email)
    try:
        EmailService.send_test(recipient)
    except EmailConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"SMTP delivery failed: {str(exc)}",
        ) from exc
    return {"message": f"Test email sent to {recipient}"}


@router.put("/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    schedule = _owned_schedule(db, current_user.current_organization_id, schedule_id)
    schedule.is_enabled = not schedule.is_enabled
    if schedule.is_enabled and not schedule.is_paused:
        schedule.next_run_at = CronExpression(schedule.cron_expression).next_after(
            datetime.now(timezone.utc),
            schedule.timezone,
        )
    else:
        schedule.next_run_at = None
    db.commit()
    asset = db.query(Asset).filter(Asset.id == schedule.asset_id).first()
    return _serialize(schedule, asset)


@router.put("/{schedule_id}/pause")
async def pause_schedule(
    schedule_id: str,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    schedule = _owned_schedule(db, current_user.current_organization_id, schedule_id)
    schedule.is_paused = not schedule.is_paused
    if schedule.is_enabled and not schedule.is_paused:
        schedule.next_run_at = CronExpression(schedule.cron_expression).next_after(
            datetime.now(timezone.utc),
            schedule.timezone,
        )
    else:
        schedule.next_run_at = None
    db.commit()
    asset = db.query(Asset).filter(Asset.id == schedule.asset_id).first()
    return _serialize(schedule, asset)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    schedule = _owned_schedule(db, current_user.current_organization_id, schedule_id)
    db.delete(schedule)
    db.commit()
    return {"message": "Schedule deleted"}

