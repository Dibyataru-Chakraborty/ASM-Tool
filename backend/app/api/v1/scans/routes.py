"""
Scans API routes for reconnaissance job management.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.discovery_service import DiscoveryService
from app.repositories.scan_repo import ScanRepository
from app.exceptions import NotFoundError, ValidationError
from app.api.v1.scans.schemas import (
    ScanInitiateRequest,
    TriggerScanRequest,
    ScanResponse,
    DomainDiscoveryRequest,
    DomainDiscoveryResponse,
    ScanListResponse,
)
from app.dependencies import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    request: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger a scan for an asset using its saved target field."""
    try:
        from app.models import Asset, Domain
        asset = db.query(Asset).filter(
            Asset.id == request.asset_id,
            Asset.user_id == current_user.id
        ).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        service = DiscoveryService(db)

        # Resolve target: use asset.target (saved from the form), fallback to asset.name
        target_value = (asset.target or asset.name or "").strip()

        # Find or create a domain entry for this target
        existing_domain = db.query(Domain).filter(Domain.asset_id == asset.id).first()
        if existing_domain:
            domain_id = existing_domain.id
        else:
            domain_name = target_value if service._is_valid_domain(target_value) else "target.local"
            domain = service.create_domain(asset.id, domain_name)
            domain_id = domain.id

        scan = service.initiate_scan(
            asset_id=asset.id,
            domain_id=domain_id,
            scan_type=request.scan_type
        )

        background_tasks.add_task(service.run_scan_simulation, scan.id, domain_id)

        return {"scan_job_id": scan.id, "status": scan.status, "asset_id": asset.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger scan: {str(e)}")


@router.post("/discover", response_model=DomainDiscoveryResponse, status_code=status.HTTP_202_ACCEPTED)
async def initiate_domain_discovery(
    request: DomainDiscoveryRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initiate domain discovery scan."""
    try:
        service = DiscoveryService(db)
        
        # Create or get domain
        domain = service.create_domain(request.asset_id, request.domain)
        
        # Initiate scan
        scan = service.initiate_scan(
            asset_id=request.asset_id,
            domain_id=domain.id,
            scan_type="discovery"
        )

        # Trigger the simulated scan in background
        background_tasks.add_task(service.run_scan_simulation, scan.id, domain.id)

        return {
            "domain_id": domain.id,
            "domain": domain.domain,
            "subdomains_found": 0,
            "dns_records_found": 0,
            "status": "pending",
            "created_at": scan.created_at,
        }
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except Exception as e:
        logger.error(f"Error initiating discovery: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate scan")


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def initiate_scan(
    request: ScanInitiateRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initiate a scan job."""
    try:
        service = DiscoveryService(db)
        
        # Resolve domain_id from target_domain if domain_id is not provided
        domain_id = request.domain_id
        if not domain_id:
            if request.target_domain:
                # Find or create domain
                domain = service.create_domain(request.asset_id, request.target_domain)
                domain_id = domain.id
            else:
                # Fallback to the first domain of this asset
                from app.models import Domain
                first_domain = db.query(Domain).filter(Domain.asset_id == request.asset_id).first()
                if first_domain:
                    domain_id = first_domain.id
                else:
                    # Create a default placeholder domain based on asset name
                    from app.models import Asset
                    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
                    domain_name = asset.name if asset else "target.local"
                    if not service._is_valid_domain(domain_name):
                        domain_name = "target.local"
                    domain = service.create_domain(request.asset_id, domain_name)
                    domain_id = domain.id
        
        scan = service.initiate_scan(
            asset_id=request.asset_id,
            domain_id=domain_id,
            scan_type=request.scan_type
        )

        # Trigger the simulated scan in background
        background_tasks.add_task(service.run_scan_simulation, scan.id, domain_id)

        return scan
    except (NotFoundError, ValidationError) as e:
        status_code = 404 if isinstance(e, NotFoundError) else 422
        raise HTTPException(status_code=status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error initiating scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate scan")


@router.get("", response_model=ScanListResponse)
async def list_scans(
    asset_id: str = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List scans for an asset or all scans for current user."""
    try:
        scan_repo = ScanRepository(db)
        if asset_id:
            scans, total = scan_repo.get_by_asset_id(asset_id, skip, limit)
        else:
            # Return all scans belonging to the current user's assets
            from app.models import Scan, Asset
            query = db.query(Scan).join(Asset).filter(Asset.user_id == current_user.id)
            total = query.count()
            scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "items": scans
        }
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan details."""
    try:
        scan_repo = ScanRepository(db)
        scan = scan_repo.get_by_id(scan_id)
        
        if not scan:
            raise NotFoundError("Scan")
        
        return scan
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logger.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan")


@router.get("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel a pending or running scan."""
    try:
        scan_repo = ScanRepository(db)
        scan = scan_repo.get_by_id(scan_id)
        
        if not scan:
            raise NotFoundError("Scan")
        
        if scan.status not in ["pending", "running"]:
            raise ValidationError("Can only cancel pending or running scans")
        
        # Update status to cancelled
        scan_repo.update_status(scan_id, "cancelled")
        
        return {"message": "Scan cancelled successfully"}
    except (NotFoundError, ValidationError) as e:
        status_code = 404 if isinstance(e, NotFoundError) else 400
        raise HTTPException(status_code=status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error cancelling scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cancel scan")
