"""Persistent recurring scan dispatcher."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone

from sqlalchemy import text

from app.config import settings
from app.models import Asset, Domain, Scan, ScanSchedule
from app.services.asset_service import AssetService
from app.services.cron_service import CronExpression
from app.services.discovery_service import DiscoveryService
from app.services.email_service import EmailService
from app.utils.database import SessionLocal


logger = logging.getLogger(__name__)

_active_lock = threading.Lock()
_active_schedule_ids: set[str] = set()


def _enable_worker_access(db) -> None:
    """Allow the trusted internal worker to read user-owned rows."""
    try:
        db.execute(text("SET app.bypass_rls = 'true'"))
    except Exception:
        db.rollback()


def _available_slots() -> int:
    with _active_lock:
        return max(0, settings.max_concurrent_scans - len(_active_schedule_ids))


def _reserve_slot(schedule_id: str) -> bool:
    with _active_lock:
        if (
            schedule_id in _active_schedule_ids
            or len(_active_schedule_ids) >= settings.max_concurrent_scans
        ):
            return False
        _active_schedule_ids.add(schedule_id)
        return True


def _release_slot(schedule_id: str) -> None:
    with _active_lock:
        _active_schedule_ids.discard(schedule_id)


def _claim_due_schedule(schedule_id: str) -> tuple[str, str] | None:
    """Atomically advance a due schedule and create its pending scan."""
    db = SessionLocal()
    try:
        _enable_worker_access(db)
        now = datetime.now(timezone.utc)
        schedule = (
            db.query(ScanSchedule)
            .filter(ScanSchedule.id == schedule_id)
            .with_for_update()
            .first()
        )
        if (
            not schedule
            or not schedule.is_enabled
            or schedule.is_paused
            or not schedule.next_run_at
            or schedule.next_run_at > now
        ):
            return None

        schedule.next_run_at = CronExpression(schedule.cron_expression).next_after(
            now,
            schedule.timezone,
        )
        schedule.last_run_at = now
        schedule.last_run_status = "queued"
        schedule.last_error = None
        schedule.notification_status = (
            "pending" if schedule.notify_on_completion else None
        )

        asset = (
            db.query(Asset)
            .filter(
                Asset.id == schedule.asset_id,
                Asset.user_id == schedule.user_id,
                Asset.status == "active",
            )
            .first()
        )
        if not asset:
            raise RuntimeError("Scheduled asset is missing, archived, or not owned by the user")

        target = AssetService._domain_from_target(asset.target or asset.name)
        if not target:
            raise RuntimeError("Scheduled asset does not contain a valid domain or URL target")

        domain = (
            db.query(Domain)
            .filter(Domain.asset_id == asset.id, Domain.domain == target)
            .first()
        )
        service = DiscoveryService(db)
        if not domain:
            domain = service.create_domain(asset.id, target)

        scan = service.initiate_scan(
            asset_id=asset.id,
            domain_id=domain.id,
            scan_type="scheduled_full",
        )
        schedule.last_scan_id = scan.id
        db.commit()
        return scan.id, domain.id
    except Exception as exc:
        db.rollback()
        logger.error("Could not queue schedule %s: %s", schedule_id, exc)
        try:
            schedule = db.query(ScanSchedule).filter(
                ScanSchedule.id == schedule_id
            ).first()
            if schedule:
                now = datetime.now(timezone.utc)
                schedule.last_run_at = now
                schedule.last_run_status = "failed"
                schedule.last_error = str(exc)[:1500]
                schedule.run_count = (schedule.run_count or 0) + 1
                schedule.fail_count = (schedule.fail_count or 0) + 1
                schedule.next_run_at = CronExpression(
                    schedule.cron_expression
                ).next_after(now, schedule.timezone)
                db.commit()
        except Exception:
            db.rollback()
            logger.exception("Could not record queue failure for schedule %s", schedule_id)
        return None
    finally:
        db.close()


def _finish_schedule(schedule_id: str, scan_id: str) -> None:
    db = SessionLocal()
    notification_payload = None
    try:
        _enable_worker_access(db)
        schedule = db.query(ScanSchedule).filter(
            ScanSchedule.id == schedule_id
        ).first()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not schedule or not scan:
            return

        final_status = scan.status
        if final_status not in {"completed", "failed", "cancelled"}:
            final_status = "failed"
            scan.status = "failed"
            scan.error_message = scan.error_message or "Scheduled scan ended without a final status"
            scan.completed_at = datetime.now(timezone.utc)

        schedule.last_run_status = final_status
        schedule.last_error = scan.error_message
        schedule.run_count = (schedule.run_count or 0) + 1
        if final_status != "completed":
            schedule.fail_count = (schedule.fail_count or 0) + 1

        asset = db.query(Asset).filter(Asset.id == schedule.asset_id).first()
        if schedule.notify_on_completion and schedule.notify_email and asset:
            notification_payload = {
                "recipient": schedule.notify_email,
                "asset_name": asset.name,
                "target": asset.target or asset.name,
                "scan_reference": scan.reference_id,
                "status": final_status,
                "discoveries": scan.discovered_count or 0,
                "vulnerabilities": scan.vulnerable_count or 0,
                "error": scan.error_message,
            }
        db.commit()
    finally:
        db.close()

    if notification_payload:
        notification_status = "sent"
        try:
            EmailService.send_schedule_result(**notification_payload)
        except Exception as exc:
            notification_status = f"failed: {str(exc)}"[:100]
            logger.error("Schedule %s email failed: %s", schedule_id, exc)

        db = SessionLocal()
        try:
            _enable_worker_access(db)
            schedule = db.query(ScanSchedule).filter(
                ScanSchedule.id == schedule_id
            ).first()
            if schedule:
                schedule.notification_status = notification_status
                db.commit()
        finally:
            db.close()


def _execute_scheduled_scan(schedule_id: str, scan_id: str, domain_id: str) -> None:
    try:
        db = SessionLocal()
        try:
            _enable_worker_access(db)
            schedule = db.query(ScanSchedule).filter(
                ScanSchedule.id == schedule_id
            ).first()
            if schedule:
                schedule.last_run_status = "running"
                db.commit()
            DiscoveryService(db).run_real_scan(scan_id, domain_id)
        finally:
            db.close()
        _finish_schedule(schedule_id, scan_id)
    except Exception:
        logger.exception("Unhandled scheduled scan failure for %s", schedule_id)
        _finish_schedule(schedule_id, scan_id)
    finally:
        _release_slot(schedule_id)


def dispatch_due_schedules() -> int:
    """Claim and launch due schedules without blocking the API process."""
    available = _available_slots()
    if available <= 0:
        return 0

    db = SessionLocal()
    try:
        _enable_worker_access(db)
        due_ids = [
            row[0]
            for row in (
                db.query(ScanSchedule.id)
                .filter(
                    ScanSchedule.is_enabled.is_(True),
                    ScanSchedule.is_paused.is_(False),
                    ScanSchedule.next_run_at.isnot(None),
                    ScanSchedule.next_run_at <= datetime.now(timezone.utc),
                )
                .order_by(ScanSchedule.next_run_at.asc())
                .limit(available)
                .all()
            )
        ]
    finally:
        db.close()

    launched = 0
    for schedule_id in due_ids:
        if not _reserve_slot(schedule_id):
            continue
        claimed = _claim_due_schedule(schedule_id)
        if not claimed:
            _release_slot(schedule_id)
            continue
        scan_id, domain_id = claimed
        threading.Thread(
            target=_execute_scheduled_scan,
            args=(schedule_id, scan_id, domain_id),
            name=f"scheduled-scan-{schedule_id[:8]}",
            daemon=True,
        ).start()
        launched += 1

    return launched


async def scheduler_loop() -> None:
    """Poll persisted schedules and dispatch due scans."""
    logger.info(
        "Scan scheduler started (poll=%ss, concurrency=%s)",
        settings.scheduler_poll_seconds,
        settings.max_concurrent_scans,
    )
    while True:
        try:
            launched = await asyncio.to_thread(dispatch_due_schedules)
            if launched:
                logger.info("Dispatched %s scheduled scan(s)", launched)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Schedule polling failed")
        await asyncio.sleep(max(5, settings.scheduler_poll_seconds))

