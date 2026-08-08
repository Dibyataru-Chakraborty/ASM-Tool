"""Celery Tasks — Scan execution and cron scheduler."""
from __future__ import annotations
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from celery import Celery
from celery.schedules import crontab
from croniter import croniter
from app.config import settings

celery_app = Celery(
    "asm_tasks",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_app.conf.update(
    task_serializer="json", result_serializer="json", accept_content=["json"],
    timezone="UTC", enable_utc=True, task_track_started=True,
    task_acks_late=True, worker_prefetch_multiplier=1,
    beat_schedule={
        "run-scheduled-scans": {
            "task":     "app.tasks.scan_tasks.check_and_run_schedules",
            "schedule": crontab(minute="*/1"),
        },
    },
)


@celery_app.task(
    bind=True, name="app.tasks.scan_tasks.run_scan_job",
    max_retries=2, default_retry_delay=60, time_limit=7200, soft_time_limit=6900,
)
def run_scan_job(self, scan_job_id: str):
    """Execute a complete scan pipeline for one scan job."""
    from app.utils.database import SessionLocal
    from app.models.scan_models import ScanJob, ASMAsset
    from app.services.scanner_pipeline import ScanPipeline
    from app.services.report_service import ReportService

    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_job_id)
        if not job:
            return {"error": "Scan job not found"}

        # Eagerly load asset before passing to async code
        asset = db.get(ASMAsset, job.asset_id)
        if not asset:
            return {"error": "Asset not found"}

        job.started_at     = datetime.utcnow()
        job.status         = "running"
        job.celery_task_id = self.request.id
        db.commit()

        pipeline   = ScanPipeline(db, scan_job_id)
        summary    = asyncio.run(pipeline.run(asset))

        report_svc = ReportService(db)
        asyncio.run(report_svc.generate(scan_job_id, summary))

        # Reload job after async ops
        db.expire_all()
        job = db.get(ScanJob, scan_job_id)
        job.status           = "completed"
        job.progress         = 100
        job.current_tool     = "done"
        job.finished_at      = datetime.utcnow()
        if job.started_at:
            job.duration_seconds = int((job.finished_at - job.started_at).total_seconds())
        db.commit()

        if job.schedule_id:
            from app.models.scan_models import ScanSchedule
            sched = db.get(ScanSchedule, job.schedule_id)
            if sched:
                sched.last_run_at     = datetime.utcnow()
                sched.last_run_status = "completed"
                sched.run_count       = (sched.run_count or 0) + 1
                sched.next_run_at     = _next_run(sched.cron_expression)
                db.commit()

        return {"status": "completed", "scan_job_id": scan_job_id, "summary": summary}

    except Exception as exc:
        db.rollback()
        try:
            job = db.get(ScanJob, scan_job_id)
            if job:
                job.status        = "failed"
                job.finished_at   = datetime.utcnow()
                job.error_message = str(exc)[:500]
                db.commit()
                if job.schedule_id:
                    from app.models.scan_models import ScanSchedule
                    sched = db.get(ScanSchedule, job.schedule_id)
                    if sched:
                        sched.last_run_status = "failed"
                        sched.fail_count      = (sched.fail_count or 0) + 1
                        sched.next_run_at     = _next_run(sched.cron_expression)
                        db.commit()
        except Exception:
            pass
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.check_and_run_schedules")
def check_and_run_schedules():
    """Check all enabled schedules and trigger due scans."""
    from app.utils.database import SessionLocal
    from app.models.scan_models import ScanSchedule, ScanJob

    db = SessionLocal()
    triggered = 0
    try:
        now = datetime.utcnow()
        schedules = (
            db.query(ScanSchedule)
            .filter(ScanSchedule.is_enabled == True,
                    ScanSchedule.is_paused  == False,
                    ScanSchedule.next_run_at <= now)
            .all()
        )
        for sched in schedules:
            running = (
                db.query(ScanJob)
                .filter(ScanJob.schedule_id == sched.id,
                        ScanJob.status.in_(["queued","running"]))
                .first()
            )
            if running:
                continue
            job = ScanJob(asset_id=sched.asset_id, schedule_id=sched.id,
                          triggered_by="schedule", status="queued")
            db.add(job); db.commit(); db.refresh(job)
            run_scan_job.delay(job.id)
            sched.next_run_at = _next_run(sched.cron_expression)
            db.commit()
            triggered += 1
        return {"triggered": triggered}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.cancel_scan_job")
def cancel_scan_job(scan_job_id: str):
    from app.utils.database import SessionLocal
    from app.models.scan_models import ScanJob
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_job_id)
        if job and job.status in ("queued","running"):
            if job.celery_task_id:
                celery_app.control.revoke(job.celery_task_id, terminate=True)
            job.status      = "cancelled"
            job.finished_at = datetime.utcnow()
            db.commit()
        return {"cancelled": scan_job_id}
    finally:
        db.close()


def _next_run(cron_expr: str) -> datetime:
    try:
        return croniter(cron_expr, datetime.utcnow()).get_next(datetime)
    except Exception:
        return datetime.utcnow() + timedelta(days=1)
