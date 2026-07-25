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
    ScanResponse,
    DomainDiscoveryRequest,
    DomainDiscoveryResponse,
    ScanListResponse,
)
from app.dependencies import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


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
    asset_id: str = Query(...),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List scans for an asset."""
    try:
        scan_repo = ScanRepository(db)
        scans, total = scan_repo.get_by_asset_id(asset_id, skip, limit)
        
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
