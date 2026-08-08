"""
Continuous Scan Scheduler
Runs scans every N hours automatically using Celery beat.
"""

from celery import Celery
from celery.schedules import crontab
from app.config import settings

celery_app = Celery(
    "asm_tasks",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        # Run full recon on all active assets every N hours
        "continuous-recon": {
            "task":     "app.tasks.scan_tasks.run_continuous_recon",
            "schedule": crontab(
                minute=0,
                hour=f"*/{settings.continuous_scan_interval_hours}",
            ),
        },
        # Check for expiring SSL certificates daily
        "ssl-expiry-check": {
            "task":     "app.tasks.scan_tasks.check_ssl_expiry",
            "schedule": crontab(hour=8, minute=0),
        },
        # Threat intel refresh every 12 hours
        "ti-refresh": {
            "task":     "app.tasks.scan_tasks.refresh_threat_intel",
            "schedule": crontab(hour="*/12", minute=30),
        },
    },
)


@celery_app.task(
    bind=True,
    name="app.tasks.scan_tasks.run_full_recon",
    max_retries=3,
    default_retry_delay=60,
    time_limit=settings.scan_timeout_seconds,
)
def run_full_recon_task(self, domain: str, asset_id: str, domain_id: str):
    """Celery task: full ProjectDiscovery recon pipeline."""
    import asyncio
    from app.utils.database import SessionLocal
    from app.services.recon_engine import FullReconEngine

    db = SessionLocal()
    try:
        engine = FullReconEngine(db)
        result = asyncio.run(
            engine.run_full_recon(domain, asset_id, domain_id)
        )
        return result
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.run_continuous_recon")
def run_continuous_recon():
    """Scheduled: run recon on all active assets."""
    from app.utils.database import SessionLocal
    from app.models.asset import Asset
    from app.models.domain import Domain

    db = SessionLocal()
    try:
        assets = db.query(Asset).filter(Asset.status == "active").all()
        dispatched = 0
        for asset in assets:
            domains = db.query(Domain).filter(Domain.asset_id == asset.id).all()
            for dom in domains:
                run_full_recon_task.delay(dom.domain, asset.id, dom.id)
                dispatched += 1
        return {"dispatched": dispatched}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.check_ssl_expiry")
def check_ssl_expiry():
    """Check for SSL certificates expiring within 30 days."""
    from app.utils.database import SessionLocal
    from app.models.domain import Domain
    from datetime import datetime, timedelta

    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() + timedelta(days=30)
        domains = db.query(Domain).filter(
            Domain.expiration_date <= cutoff.isoformat()
        ).all()
        return {"expiring_domains": [d.domain for d in domains]}
    finally:
        db.close()


@celery_app.task(name="app.tasks.scan_tasks.refresh_threat_intel")
def refresh_threat_intel():
    """Refresh threat intel for all tracked IPs."""
    import asyncio
    from app.utils.database import SessionLocal
    from app.models.subdomain import Subdomain
    from app.services.threat_intel_service import enrich_ip

    db = SessionLocal()
    try:
        subs = db.query(Subdomain).filter(Subdomain.is_responsive == True).all()
        all_ips = list({ip for s in subs for ip in (s.ip_addresses or [])})
        results = asyncio.run(asyncio.gather(*[enrich_ip(ip) for ip in all_ips[:50]]))
        return {"enriched_ips": len(results)}
    finally:
        db.close()
