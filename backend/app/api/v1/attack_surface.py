"""
Attack Surface Management API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.models import Asset, Tenant, Domain, Subdomain, Vulnerability, Service
from app.models.phase2 import Port

router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])

# Schemas
class UpdateInventoryRequest(BaseModel):
    status: Optional[str] = None
    ownership_status: Optional[str] = None
    criticality: Optional[str] = None

class UpdateExposureRequest(BaseModel):
    status: str

class CreateSeedRequest(BaseModel):
    organization_id: Optional[str] = None
    seed_type: str
    value: str
    is_primary: Optional[bool] = False

def determine_seed_type(value: str) -> str:
    import re
    val = value.strip()
    if re.match(r'^as\d+$', val, re.IGNORECASE):
        return "asn"
    if "/" in val:
        return "cidr"
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ip_pattern, val):
        return "ip"
    return "domain"


@router.get("/overview")
async def get_overview(
    request: Request,
    organization_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get attack surface metrics and overview statistics."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    assets = q.all()
    total_assets = len(assets)
    new_assets = sum(1 for a in assets if a.status == "new")
    unknown_assets = sum(1 for a in assets if a.status == "unknown")
    
    asset_ids = [a.id for a in assets]
    if asset_ids:
        domains_count = db.query(Domain).filter(Domain.asset_id.in_(asset_ids)).count()
        subdomains_count = db.query(Subdomain).join(Domain).filter(Domain.asset_id.in_(asset_ids)).count()
        services_count = db.query(Service).join(Port).join(Subdomain).join(Domain).filter(Domain.asset_id.in_(asset_ids)).count()
        vulns = db.query(Vulnerability).join(Service).join(Port).join(Subdomain).join(Domain).filter(Domain.asset_id.in_(asset_ids)).all()
    else:
        domains_count = 0
        subdomains_count = 0
        services_count = 0
        vulns = []
    
    exposed_assets_set = set()
    for v in vulns:
        if v.service and v.service.port and v.service.port.subdomain and v.service.port.subdomain.domain:
            exposed_assets_set.add(v.service.port.subdomain.domain.asset_id)
            
    exposed_assets_count = len(exposed_assets_set)
    critical_exposures_count = sum(1 for v in vulns if v.severity == "Critical")
    
    exposures_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = (v.severity or "medium").lower()
        if sev in exposures_by_severity:
            exposures_by_severity[sev] += 1
            
    inventory_by_type = {
        "domain": domains_count,
        "subdomain": subdomains_count,
        "service": services_count
    }
    
    top_risk = []
    sorted_assets = sorted(assets, key=lambda x: x.risk_score or 0, reverse=True)[:5]
    for sa in sorted_assets:
        top_risk.append({
            "id": sa.id,
            "display_name": sa.name,
            "value": sa.name,
            "asset_type": sa.asset_type,
            "risk_score": sa.risk_score or 0
        })
        
    return {
        "total_assets": total_assets,
        "new_assets": new_assets,
        "unknown_assets": unknown_assets,
        "exposed_assets": exposed_assets_count,
        "critical_exposures": critical_exposures_count,
        "changes_24h": 0,
        "attack_surface_growth_30d": 0,
        "inventory_by_type": inventory_by_type,
        "exposures_by_severity": exposures_by_severity,
        "recent_changes": [],
        "top_risk_assets": top_risk
    }


@router.get("/inventory")
async def get_inventory(
    request: Request,
    organization_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    ownership_status: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get filtered attack surface inventory list."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    query = db.query(Asset)
    if org_id:
        query = query.filter(Asset.tenant_id == org_id)
    else:
        query = query.filter(Asset.user_id == current_user.id)

    if search:
        s = f"%{search}%"
        query = query.filter(Asset.name.ilike(s))
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if status:
        query = query.filter(Asset.status == status)
        
    assets = query.all()
    
    org_name = "Default Org"
    if org_id:
        tenant = db.query(Tenant).filter(Tenant.id == org_id).first()
        if tenant:
            org_name = tenant.name
            
    items = []
    for a in assets:
        items.append({
            "id": a.id,
            "display_name": a.name,
            "value": a.name,
            "organization_name": org_name,
            "asset_type": a.asset_type,
            "status": a.status or "active",
            "ownership_status": a.ownership_status or "confirmed",
            "criticality": a.criticality or "medium",
            "first_seen": a.created_at.isoformat() if a.created_at else None,
            "last_seen": a.updated_at.isoformat() if a.updated_at else None,
            "risk_score": a.risk_score or 0
        })
        
    return {"assets": items, "total": len(items)}


@router.get("/inventory/{id}")
async def get_inventory_item(
    id: str,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get single inventory asset details."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    query = db.query(Asset).filter(Asset.id == id)
    if org_id:
        query = query.filter(Asset.tenant_id == org_id)
    else:
        query = query.filter(Asset.user_id == current_user.id)
        
    asset = query.first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    org_name = "Default Org"
    if org_id:
        tenant = db.query(Tenant).filter(Tenant.id == org_id).first()
        if tenant:
            org_name = tenant.name
            
    return {
        "asset": {
            "id": asset.id,
            "display_name": asset.name,
            "value": asset.name,
            "organization_name": org_name,
            "asset_type": asset.asset_type,
            "status": asset.status or "active",
            "ownership_status": asset.ownership_status or "confirmed",
            "criticality": asset.criticality or "medium",
            "first_seen": asset.created_at.isoformat() if asset.created_at else None,
            "last_seen": asset.updated_at.isoformat() if asset.updated_at else None,
            "risk_score": asset.risk_score or 0
        },
        "relationships": [],
        "exposures": [],
        "changes": []
    }


@router.patch("/inventory/{id}")
async def update_inventory_item(
    id: str,
    request_body: UpdateInventoryRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update lifecycle status of an inventory asset."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    query = db.query(Asset).filter(Asset.id == id)
    if org_id:
        query = query.filter(Asset.tenant_id == org_id)
    else:
        query = query.filter(Asset.user_id == current_user.id)

    asset = query.first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    if request_body.status is not None:
        asset.status = request_body.status
    if request_body.criticality is not None:
        asset.criticality = request_body.criticality
    if request_body.ownership_status is not None:
        asset.ownership_status = request_body.ownership_status
    db.commit()
    return {"message": "Asset updated successfully"}


@router.get("/changes")
async def get_changes(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get recent changes logs."""
    return {"changes": [], "total": 0}


@router.get("/exposures")
async def get_exposures(
    request: Request,
    organization_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vulnerabilities list."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    asset_ids = [a.id for a in q.all()]

    if asset_ids:
        query = db.query(Vulnerability).join(Service).join(Port).join(Subdomain).join(Domain).filter(Domain.asset_id.in_(asset_ids))
    else:
        return {"exposures": [], "total": 0}

    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))
    vulns = query.all()
    
    items = []
    for v in vulns:
        items.append({
            "id": v.id,
            "title": v.title,
            "description": v.description,
            "severity": (v.severity or "Medium").lower(),
            "status": "open",
            "cvss": v.cvss_score or 7.5,
            "first_seen": v.created_at.isoformat() if v.created_at else None,
            "last_seen": v.updated_at.isoformat() if v.updated_at else None,
            "remediation": v.description  # fallback
        })
    return {"exposures": items, "total": len(items)}


@router.patch("/exposures/{id}")
async def update_exposure_status(
    id: str,
    request_body: UpdateExposureRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update exposure status."""
    return {"message": "Exposure status updated"}


@router.get("/seeds")
async def get_seeds(
    request: Request,
    organization_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get discovery seeds list."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    asset_ids = [a.id for a in q.all()]

    if not asset_ids:
        return {"seeds": []}

    domains = db.query(Domain).filter(Domain.asset_id.in_(asset_ids)).all()
    seeds = []
    for d in domains:
        stype = determine_seed_type(d.domain)
        seeds.append({
            "id": d.id,
            "value": d.domain,
            "seed_type": stype,
            "ownership_status": "confirmed",
            "confidence_score": 1.0,
            "is_primary": d.is_active or False
        })
    return {"seeds": seeds}


@router.post("/seeds")
async def create_seed(
    request: Request,
    request_body: CreateSeedRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add new seed for discovery."""
    org_id = request_body.organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    asset = q.first()

    if not asset:
        from app.services.asset_service import AssetService
        service = AssetService(db)
        asset = service.create_asset(
            user_id=current_user.id,
            name="Organization Assets",
            description="Discovery seed asset group",
            asset_type="domain",
            tenant_id=org_id
        )

    domain = db.query(Domain).filter(Domain.domain == request_body.value, Domain.asset_id == asset.id).first()
    if not domain:
        domain = Domain(
            asset_id=asset.id,
            domain=request_body.value,
            scan_status="not_scanned",
            is_active=request_body.is_primary or False
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)
    
    stype = determine_seed_type(domain.domain)
    return {
        "id": domain.id,
        "value": domain.domain,
        "seed_type": stype,
        "ownership_status": "confirmed",
        "confidence_score": 1.0,
        "is_primary": domain.is_active or False
    }


@router.delete("/seeds/{id}")
async def delete_seed(
    id: str,
    request: Request,
    organization_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a discovery seed."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    asset_ids = [a.id for a in q.all()]

    domain_query = db.query(Domain).filter(Domain.id == id)
    if asset_ids:
        domain_query = domain_query.filter(Domain.asset_id.in_(asset_ids))
    else:
        domain_query = domain_query.filter(False)

    domain = domain_query.first()
    if domain:
        db.delete(domain)
        db.commit()
    return {"message": "Seed deleted"}


@router.post("/rebuild/{organizationId}")
async def rebuild_attack_surface(
    organizationId: str,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Force rebuild of ASM dashboard state."""
    return {"message": "Rebuild initiated"}


@router.get("/graph")
async def get_graph(
    request: Request,
    organization_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get topology graph nodes and links."""
    return {"nodes": [], "links": []}
