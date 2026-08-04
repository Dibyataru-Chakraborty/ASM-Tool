"""
Main FastAPI application for ASM Platform.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
from contextlib import asynccontextmanager, suppress
import logging
from app.config import settings
from app.utils.logger import logger
from app.utils.database import init_db, close_db
from app.exceptions import ASMException
from app.api.v1.router import router as v1_router
from app.services.scheduler_service import scheduler_loop


# Setup logging
logging.basicConfig(level=settings.log_level)


def reconcile_interrupted_scans() -> int:
    """Fail in-process scan jobs that could not survive a backend restart."""
    from datetime import datetime, timezone

    from app.models import Domain, Scan
    from app.utils.database import SessionLocal

    db = SessionLocal()
    try:
        interrupted = db.query(Scan).filter(Scan.status.in_(("pending", "running"))).all()
        if not interrupted:
            return 0

        completed_at = datetime.now(timezone.utc)
        for scan in interrupted:
            previous_status = scan.status
            scan.status = "failed"
            scan.completed_at = completed_at
            scan.error_message = (
                f"Scan was interrupted while {previous_status} because the backend restarted. "
                "Start a new scan to run the complete tool pipeline."
            )
            domain = db.query(Domain).filter(
                Domain.asset_id == scan.asset_id,
                Domain.domain == scan.target_domain,
            ).first()
            if domain and domain.scan_status == "scanning":
                domain.scan_status = "failed"
        db.commit()
        return len(interrupted)
    except Exception:
        db.rollback()
        logger.exception("Could not reconcile interrupted scan jobs")
        return 0
    finally:
        db.close()


def backfill_scan_archives() -> int:
    """Create missing compressed snapshots for scans already in the database."""
    from app.services.scan_archive_service import ScanArchiveService
    from app.utils.database import SessionLocal

    db = SessionLocal()
    try:
        return ScanArchiveService().backfill_missing(db)
    except Exception:
        logger.exception("Could not backfill historical scan archives")
        return 0
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager."""
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    init_db()
    logger.info("Database initialized")
    interrupted_count = reconcile_interrupted_scans()
    if interrupted_count:
        logger.warning(
            "Marked %s interrupted scan job(s) as failed after restart",
            interrupted_count,
        )
    archived_count = backfill_scan_archives()
    if archived_count:
        logger.info("Created %s missing historical scan archive(s)", archived_count)
    schedule_task = asyncio.create_task(scheduler_loop())

    yield

    # Shutdown
    logger.info("Shutting down application")
    schedule_task.cancel()
    with suppress(asyncio.CancelledError):
        await schedule_task
    close_db()
    logger.info("Database connections closed")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    description="Enterprise-grade Attack Surface Management Platform",
    version=settings.api_version,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_credentials,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
)


# Exception handlers
@app.exception_handler(ASMException)
async def asm_exception_handler(request: Request, exc: ASMException):
    """Handle ASM exceptions."""
    logger.error(f"ASM Exception: {exc.code} - {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
        },
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


# Ready check endpoint
@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint."""
    from app.utils.database import engine
    try:
        # Test database connection
        with engine.connect() as conn:
            pass
        return {
            "status": "ready",
            "database": "connected",
        }
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "database": "disconnected",
                "error": str(e),
            },
        )


# API Routes
app.include_router(v1_router)

# Real gowitness captures. The API returns these URLs to the frontend.
import os
os.makedirs("/app/screenshots", exist_ok=True)
app.mount("/screenshots", StaticFiles(directory="/app/screenshots"), name="screenshots")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers,
        log_level=settings.log_level.lower(),
    )
