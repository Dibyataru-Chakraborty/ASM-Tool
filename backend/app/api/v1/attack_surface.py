"""Organization-centric Attack Surface Management API."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, require_org_admin, require_tenant_member
from app.models import Asset, Organization, DiscoverySeed, Domain, Scan
from app.services.asset_service import AssetService
from app.services.attack_surface_service import AttackSurfaceService
from app.services.discovery_service import DiscoveryService
from app.utils.database import get_db


router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])


class SeedCreateRequest(BaseModel):
    organization_id: str
    seed_type: str = Field(default="domain", pattern="^(domain|ip|cidr|asn)$")
    value: str = Field(..., min_length=1, max_length=512)
    is_primary: bool = False


class InventoryContextUpdate(BaseModel):
    criticality: Optional[str] = Field(None, pattern="^(critical|high|normal|low)$")
    ownership_status: Optional[str] = Field(
        None,
        pattern="^(confirmed|high_confidence|requires_investigation|rejected)$",
    )


class ExposureStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(open|in_progress|accepted_risk|false_positive|resolved)$",
    )


def _owned_organization(db: Session, current_user, organization_id: str) -> Organization:
    if current_user.platform_role != "super_admin" and organization_id != current_user.current_organization_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    row=db.query(Organization).filter(Organization.id==organization_id,Organization.status=="active").first()
    if not row: raise HTTPException(status_code=404,detail="Organization not found")
    return row


@router.get("/overview")
async def overview(
    organization_id: Optional[str] = Query(None),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    if organization_id:
        _owned_organization(db, current_user, organization_id)
    return AttackSurfaceService(db).overview(current_user.current_organization_id, organization_id)


@router.get("/graph")
async def asset_graph(
    organization_id: str = Query(...),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    _owned_organization(db, current_user, organization_id)
    try:
        return AttackSurfaceService(db).graph(current_user.current_organization_id, organization_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/inventory")
async def inventory(
    organization_id: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    ownership_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    if organization_id:
        _owned_organization(db, current_user, organization_id)
    return AttackSurfaceService(db).list_inventory(
        current_user.current_organization_id,
        organization_id=organization_id,
        asset_type=asset_type,
        status=status_filter,
        ownership_status=ownership_status,
        search=search,
        limit=limit,
    )


@router.get("/inventory/{discovered_asset_id}")
async def inventory_detail(
    discovered_asset_id: str,
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    try:
        return AttackSurfaceService(db).asset_detail(current_user.current_organization_id, discovered_asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/inventory/{discovered_asset_id}")
async def update_inventory_context(
    discovered_asset_id: str,
    request: InventoryContextUpdate,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    try:
        row = AttackSurfaceService(db).update_asset_context(
            current_user.current_organization_id,
            discovered_asset_id,
            criticality=request.criticality,
            ownership_status=request.ownership_status,
        )
        organization = db.query(Asset).filter(Asset.id == row.organization_id).first()
        return AttackSurfaceService._serialize_asset(
            row, organization.name if organization else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/changes")
async def changes(
    organization_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    if organization_id:
        _owned_organization(db, current_user, organization_id)
    return AttackSurfaceService(db).list_changes(
        current_user.current_organization_id,
        organization_id=organization_id,
        limit=limit,
    )


@router.get("/exposures")
async def exposures(
    organization_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    exposure_status: Optional[str] = Query(None, alias="status"),
    limit: int = Query(200, ge=1, le=1000),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    if organization_id:
        _owned_organization(db, current_user, organization_id)
    return AttackSurfaceService(db).list_exposures(
        current_user.current_organization_id,
        organization_id=organization_id,
        status=exposure_status,
        severity=severity,
        limit=limit,
    )


@router.patch("/exposures/{exposure_id}")
async def update_exposure_status(
    exposure_id: str,
    request: ExposureStatusUpdate,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    try:
        row = AttackSurfaceService(db).update_exposure_status(
            current_user.current_organization_id, exposure_id, request.status
        )
        return {
            "id": row.id,
            "status": row.status,
            "risk_score": row.risk_score,
            "resolved_at": row.resolved_at,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/seeds")
async def list_seeds(
    organization_id: str = Query(...),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    _owned_organization(db, current_user, organization_id)
    seeds = db.query(DiscoverySeed).filter(
        DiscoverySeed.organization_id == organization_id
    ).order_by(DiscoverySeed.is_primary.desc(), DiscoverySeed.created_at.asc()).all()
    return {
        "seeds": [
            {
                "id": seed.id,
                "organization_id": seed.organization_id,
                "seed_type": seed.seed_type,
                "value": seed.value,
                "is_primary": seed.is_primary,
                "is_active": seed.is_active,
                "ownership_status": seed.ownership_status,
                "confidence_score": seed.confidence_score,
                "created_at": seed.created_at,
            }
            for seed in seeds
        ],
        "total": len(seeds),
    }


@router.post("/seeds", status_code=status.HTTP_201_CREATED)
async def create_seed(
    request: SeedCreateRequest,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    organization = _owned_organization(db, current_user, request.organization_id)
    value = request.value.strip().lower()
    if request.seed_type == "domain":
        domain_value = AssetService._domain_from_target(value)
        if not domain_value:
            raise HTTPException(status_code=422, detail="Enter a valid domain seed")
        value = domain_value
    if request.is_primary:
        db.query(DiscoverySeed).filter(
            DiscoverySeed.organization_id == organization.id,
            DiscoverySeed.is_primary.is_(True),
        ).update({DiscoverySeed.is_primary: False}, synchronize_session=False)
    existing = db.query(DiscoverySeed).filter(
        DiscoverySeed.organization_id == organization.id,
        DiscoverySeed.seed_type == request.seed_type,
        DiscoverySeed.value == value,
    ).first()
    if existing:
        existing.is_active = True
        if request.is_primary:
            existing.is_primary = True
        db.commit()
        seed = existing
    else:
        seed = DiscoverySeed(
            organization_id=organization.id,
            seed_type=request.seed_type,
            value=value,
            is_primary=request.is_primary,
            is_active=True,
            ownership_status="confirmed",
            confidence_score=1.0,
        )
        db.add(seed)
        if request.seed_type == "domain":
            domain = db.query(Domain).filter(
                Domain.organization_id == organization.id,
                Domain.domain == value,
            ).first()
            if not domain:
                root_asset = db.query(Asset).filter(Asset.organization_id == organization.id, Asset.status != "archived").first()
                if not root_asset:
                    raise HTTPException(status_code=422, detail="Add an organization domain/asset before adding this seed")
                DiscoveryService(db).create_domain(root_asset.id, value)
        db.commit()
        db.refresh(seed)
    return {
        "id": seed.id,
        "organization_id": seed.organization_id,
        "seed_type": seed.seed_type,
        "value": seed.value,
        "is_primary": seed.is_primary,
        "is_active": seed.is_active,
        "ownership_status": seed.ownership_status,
        "confidence_score": seed.confidence_score,
        "created_at": seed.created_at,
    }


@router.delete("/seeds/{seed_id}")
async def delete_seed(
    seed_id: str,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    seed = db.query(DiscoverySeed).filter(
        DiscoverySeed.id == seed_id,
        DiscoverySeed.organization_id == current_user.current_organization_id,
    ).first()
    if not seed:
        raise HTTPException(status_code=404, detail="Discovery seed not found")
    if seed.is_primary:
        raise HTTPException(status_code=400, detail="Primary discovery seed cannot be removed")
    db.delete(seed)
    db.commit()
    return {"message": "Discovery seed removed"}


@router.post("/rebuild/{organization_id}")
async def rebuild_inventory(
    organization_id: str,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    """Build ASM state from the latest completed scan for each known domain."""
    organization = _owned_organization(db, current_user, organization_id)
    domains = db.query(Domain).filter(Domain.organization_id == organization.id).all()
    service = AttackSurfaceService(db)
    synced = []
    for domain in domains:
        scan = db.query(Scan).filter(
            Scan.organization_id == organization.id,
            Scan.target_domain == domain.domain,
            Scan.status == "completed",
        ).order_by(Scan.completed_at.desc(), Scan.created_at.desc()).first()
        if not scan:
            continue
        synced.append({"scan_id": scan.id, "domain": domain.domain, **service.sync_from_scan(scan.id, domain.id)})
    return {"organization_id": organization.id, "synced": synced, "total": len(synced)}
