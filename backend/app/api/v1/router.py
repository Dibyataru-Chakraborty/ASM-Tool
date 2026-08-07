"""
API v1 router aggregating all route modules.
"""

from fastapi import APIRouter
from app.api.v1.auth.routes import router as auth_router
from app.api.v1.assets.routes import router as assets_router
from app.api.v1.scans.routes import router as scans_router
from app.api.v1.dashboard.routes import router as dashboard_router
from app.api.v1.ai_analysis import router as ai_analysis_router
from app.api.v1.super_admin import super_admin_router, organization_router
from app.api.v1.attack_surface import router as attack_surface_router
from app.api.v1.recon import router as recon_router

# Create main v1 router
router = APIRouter(prefix="/api/v1")

# Include all route modules
router.include_router(auth_router)
router.include_router(assets_router)
router.include_router(scans_router)
router.include_router(dashboard_router)
router.include_router(ai_analysis_router)
router.include_router(super_admin_router)
router.include_router(organization_router)
router.include_router(attack_surface_router)
router.include_router(recon_router)

# Include advanced phase routers
from app.api.v1.phases_2_to_10 import (
    ports_router, vuln_router, ti_router, secrets_router,
    alerts_router, ai_router, enterprise_router, reports_router, backup_router,
    shannon_router
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
router.include_router(shannon_router)

__all__ = ["router"]
