"""
ASM Platform — Merged Main Application
Digi Samurai EASM - FastAPI backend
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from app.config import settings
from app.utils.logger import logger
from app.utils.database import init_db, close_db
from app.exceptions import ASMException

logging.basicConfig(level=settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down")
    close_db()


app = FastAPI(
    title=settings.api_title if hasattr(settings, 'api_title') else "Digi Samurai ASM Platform",
    description="Enterprise Attack Surface Management Platform",
    version=settings.api_version if hasattr(settings, 'api_version') else "2.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list if hasattr(settings, 'cors_origins_list') else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ASMException)
async def asm_exception_handler(request: Request, exc: ASMException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled: {exc}", exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR", "message": str(exc)})


@app.get("/health")
async def health_check():
    return {"status": "healthy", "app": settings.app_name}


@app.get("/ready")
async def readiness_check():
    from app.utils.database import engine
    try:
        with engine.connect():
            pass
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(e)})


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.app_name}", "docs": "/docs"}


# Main unified router
from app.api.v1.router import router as v1_router
from app.dependencies import check_write_permission
from fastapi import Depends
app.include_router(v1_router, dependencies=[Depends(check_write_permission)])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
