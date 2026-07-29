"""
Assets API routes for managing reconnaissance targets.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.asset_service import AssetService
from app.exceptions import NotFoundError, ConflictError, ValidationError
from app.api.v1.assets.schemas import (
    AssetCreateRequest,
    AssetUpdateRequest,
    AssetResponse,
    AssetDetailResponse,
    AssetListResponse,
    AssetStatsResponse,
    DomainCreateRequest,
    DomainResponse,
)
from app.dependencies import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    request: AssetCreateRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new asset."""
    try:
        service = AssetService(db)
        asset = service.create_asset(
            user_id=current_user.id,
            name=request.name,
            target=request.target,
            description=request.description,
            asset_type=request.asset_type,
            tags=request.tags or [],
        )
        return AssetResponse.from_orm_asset(asset)
    except (ConflictError, ValidationError) as e:
        status_code = 409 if isinstance(e, ConflictError) else 422
        raise HTTPException(status_code=status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error creating asset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create asset")


@router.get("", response_model=AssetListResponse)
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    search: str = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all assets for current user."""
    try:
        service = AssetService(db)
        assets, total = service.list_active_assets(current_user.id, skip, limit)
        if search:
            normalized_search = search.lower()
            assets = [
                asset for asset in assets
                if normalized_search in (asset.name or "").lower()
                or normalized_search in (asset.target or "").lower()
            ]
            total = len(assets)
        serialized = [AssetResponse.from_orm_asset(asset) for asset in assets]
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "items": serialized,
            "assets": serialized,
        }
    except Exception as e:
        logger.error(f"Error listing assets: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list assets")


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset details."""
    try:
        service = AssetService(db)
        asset = service.get_asset(asset_id, current_user.id)
        stats = service.get_asset_stats(asset_id, current_user.id)

        base = AssetResponse.from_orm_asset(asset)
        return {
            **base.model_dump(),
            "total_domains": stats["total_domains"],
            "total_subdomains": stats["total_subdomains"],
            "vulnerable_domains": stats["vulnerable_domains"],
        }
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"Error getting asset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get asset")


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    request: AssetUpdateRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an asset."""
    try:
        service = AssetService(db)
        asset = service.update_asset(
            asset_id=asset_id,
            user_id=current_user.id,
            name=request.name,
            target=request.target,
            description=request.description,
            status=request.status,
            asset_type=request.asset_type,
            tags=request.tags,
        )
        return AssetResponse.from_orm_asset(asset)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except (ValidationError, ConflictError) as e:
        status_code = 422 if isinstance(e, ValidationError) else 409
        raise HTTPException(status_code=status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error updating asset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update asset")


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an asset."""
    try:
        service = AssetService(db)
        service.delete_asset(asset_id, current_user.id)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"Error deleting asset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete asset")


@router.post("/{asset_id}/archive", response_model=AssetResponse)
async def archive_asset(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Archive an asset (soft delete)."""
    try:
        service = AssetService(db)
        asset = service.archive_asset(asset_id, current_user.id)
        return asset
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"Error archiving asset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to archive asset")


@router.get("/{asset_id}/stats", response_model=AssetStatsResponse)
async def get_asset_stats(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset statistics."""
    try:
        service = AssetService(db)
        stats = service.get_asset_stats(asset_id, current_user.id)
        return stats
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"Error getting asset stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get asset stats")


@router.get("/{asset_id}/domains", response_model=list[DomainResponse])
async def get_asset_domains(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of domains for an asset."""
    from app.models import Domain, Asset

    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    domains = db.query(Domain).filter(Domain.asset_id == asset_id).all()

    # Auto-initialize domain if the asset itself is a domain and none exist
    if not domains and asset.asset_type == "domain":
        from app.services.discovery_service import DiscoveryService
        discovery_service = DiscoveryService(db)
        if discovery_service._is_valid_domain(asset.name):
            try:
                discovery_service.create_domain(asset.id, asset.name)
                domains = db.query(Domain).filter(Domain.asset_id == asset_id).all()
            except Exception as e:
                logger.error(f"Failed to auto-initialize domain for asset: {str(e)}")

    result = []
    for d in domains:
        # Count subdomains
        from app.models import Subdomain
        sub_count = db.query(Subdomain).filter(Subdomain.domain_id == d.id).count()

        result.append({
            "id": d.id,
            "domain": d.domain,
            "tld": d.tld,
            "registrar": d.registrar,
            "expiration_date": d.expiration_date,
            "is_vulnerable": d.is_vulnerable,
            "last_scanned": d.last_scanned,
            "subdomain_count": sub_count,
            "created_at": d.created_at
        })
    return result


@router.get("/{asset_id}/subdomains")
async def get_asset_subdomains(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of subdomains for an asset."""
    from app.models import Domain, Subdomain, Asset
    from app.models.phase2 import Port
    
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    subdomains = db.query(Subdomain).join(Domain).filter(Domain.asset_id == asset_id).all()
    
    result = []
    for s in subdomains:
        ports = db.query(Port).filter(Port.subdomain_id == s.id).all()
        result.append({
            "id": s.id,
            "subdomain": s.subdomain,
            "ip_addresses": __import__('json').loads(s.ip_addresses) if s.ip_addresses else [],
            "is_responsive": s.is_responsive,
            "response_status_code": s.response_status_code,
            "has_ssl": s.has_ssl,
            "ports": [p.port_number for p in ports]
        })
    return {"subdomains": result, "total": len(result)}


@router.get("/{asset_id}/screenshots")
async def get_asset_screenshots(
    asset_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of screenshots for an asset."""
    from app.models import Domain, Subdomain, Asset, Screenshot
    
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.user_id == current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    screenshots = db.query(Screenshot).join(Subdomain).join(Domain).filter(Domain.asset_id == asset_id).all()
    
    result = []
    for s in screenshots:
        result.append({
            "id": s.id,
            "subdomain_id": s.subdomain_id,
            "url": s.url,
            "protocol": s.protocol,
            "port": s.port,
            "file_path": s.file_path,
            "status_code": s.status_code,
            "title": s.title,
            "technologies": __import__('json').loads(s.technologies) if s.technologies else []
        })
    return {"screenshots": result, "total": len(result)}

