"""
Scans API routes for reconnaissance job management.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.discovery_service import (
    DiscoveryService,
    clear_live_scan_state,
    get_live_scan_state,
)
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


def _scan_payload(scan) -> dict:
    """Add factual in-process progress to the persisted scan record."""
    payload = {
        column.name: getattr(scan, column.name)
        for column in scan.__table__.columns
    }
    live_state = get_live_scan_state(scan.id)
    payload["current_tool"] = live_state.get("current_tool")
    payload["progress"] = live_state.get(
        "progress",
        100 if scan.status == "completed" else 0,
    )
    return payload


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

        # Resolve the real hostname stored on the owned asset.
        from app.services.asset_service import AssetService
        target_value = AssetService._domain_from_target(asset.target or asset.name)
        if not target_value:
            raise HTTPException(
                status_code=422,
                detail="This scan requires a domain or URL asset with a valid hostname",
            )

        # Find or create a domain entry for this target
        existing_domain = db.query(Domain).filter(
            Domain.asset_id == asset.id,
            Domain.domain == target_value,
        ).first()
        if existing_domain:
            domain_id = existing_domain.id
        else:
            domain = service.create_domain(asset.id, target_value)
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
        from app.models import Asset
        asset = db.query(Asset).filter(
            Asset.id == request.asset_id,
            Asset.user_id == current_user.id,
        ).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        service = DiscoveryService(db)
        
        # Create or get domain
        domain = service.create_domain(request.asset_id, request.domain)
        
        # Initiate scan
        scan = service.initiate_scan(
            asset_id=request.asset_id,
            domain_id=domain.id,
            scan_type="discovery"
        )

        # Trigger the real scanner in background
        background_tasks.add_task(service.run_scan_simulation, scan.id, domain.id)

        return {
            "domain_id": domain.id,
            "domain": domain.domain,
            "subdomains_found": 0,
            "dns_records_found": 0,
            "status": "pending",
            "created_at": scan.created_at,
        }
    except HTTPException:
        raise
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
        from app.models import Asset, Domain
        asset = db.query(Asset).filter(
            Asset.id == request.asset_id,
            Asset.user_id == current_user.id,
        ).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        service = DiscoveryService(db)
        
        # Resolve domain_id from target_domain if domain_id is not provided
        domain_id = request.domain_id
        if not domain_id:
            if request.target_domain:
                # Find or create domain
                domain = service.create_domain(request.asset_id, request.target_domain)
                domain_id = domain.id
            else:
                # Fall back to the selected asset's saved, valid target.
                first_domain = db.query(Domain).filter(Domain.asset_id == request.asset_id).first()
                if first_domain:
                    domain_id = first_domain.id
                else:
                    from app.services.asset_service import AssetService
                    domain_name = AssetService._domain_from_target(asset.target or asset.name)
                    if not domain_name:
                        raise ValidationError(
                            "This scan requires a domain or URL asset with a valid hostname"
                        )
                    domain = service.create_domain(request.asset_id, domain_name)
                    domain_id = domain.id
        
        scan = service.initiate_scan(
            asset_id=request.asset_id,
            domain_id=domain_id,
            scan_type=request.scan_type
        )

        # Trigger the real scanner in background
        background_tasks.add_task(service.run_scan_simulation, scan.id, domain_id)

        return scan
    except HTTPException:
        raise
    except (NotFoundError, ValidationError) as e:
        status_code = 404 if isinstance(e, NotFoundError) else 422
        raise HTTPException(status_code=status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error initiating scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate scan")


@router.get("", response_model=ScanListResponse)
async def list_scans(
    asset_id: str = Query(None),
    search: str = Query(None, min_length=1, max_length=100),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List scans for an asset or all scans for current user."""
    try:
        from app.models import Asset, Scan

        query = db.query(Scan).join(Asset).filter(Asset.user_id == current_user.id)
        if asset_id:
            owned_asset = db.query(Asset).filter(
                Asset.id == asset_id,
                Asset.user_id == current_user.id,
            ).first()
            if not owned_asset:
                raise HTTPException(status_code=404, detail="Asset not found")
            query = query.filter(Scan.asset_id == asset_id)

        if search:
            # Escape SQL wildcard characters so a pasted scan reference is
            # always treated as literal text while still allowing partial IDs.
            escaped = (
                search.strip()
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"
            query = query.filter(or_(
                Scan.reference_id.ilike(pattern, escape="\\"),
                Scan.id.ilike(pattern, escape="\\"),
            ))

        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "items": [_scan_payload(scan) for scan in scans]
        }
    except HTTPException:
        raise
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
        from app.models import Asset, Scan
        scan = db.query(Scan).join(Asset).filter(
            Scan.id == scan_id,
            Asset.user_id == current_user.id,
        ).first()
        
        if not scan:
            raise NotFoundError("Scan")
        
        return _scan_payload(scan)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logger.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan")


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel a pending or running scan."""
    try:
        from app.models import Asset, Scan
        scan_repo = ScanRepository(db)
        scan = db.query(Scan).join(Asset).filter(
            Scan.id == scan_id,
            Asset.user_id == current_user.id,
        ).first()
        
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

@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Permanently delete one scan owned by the current user."""
    try:
        from app.models import (
            AIServiceAssessment,
            Asset,
            Scan,
            ScanSchedule,
        )

        scan = (
            db.query(Scan)
            .join(Asset)
            .filter(
                Scan.id == scan_id,
                Asset.user_id == current_user.id,
            )
            .first()
        )

        if not scan:
            raise NotFoundError("Scan")

        # Do not remove an active scan while scanner commands are executing.
        if scan.status in ["pending", "running"]:
            raise ValidationError(
                "Cancel the running or queued scan before deleting it"
            )

        reference_id = scan.reference_id

        # Delete Gemini assessments connected to this scan.
        db.query(AIServiceAssessment).filter(
            AIServiceAssessment.scan_id == scan_id
        ).delete(synchronize_session=False)

        # Remove the deleted scan from schedule history.
        db.query(ScanSchedule).filter(
            ScanSchedule.last_scan_id == scan_id
        ).update(
            {ScanSchedule.last_scan_id: None},
            synchronize_session=False,
        )

        # Permanently delete the scan history record.
        db.delete(scan)
        db.commit()

        clear_live_scan_state(scan_id)

        return {
            "message": "Scan deleted permanently",
            "scan_id": scan_id,
            "reference_id": reference_id,
        }

    except (NotFoundError, ValidationError) as exc:
        db.rollback()

        status_code = (
            status.HTTP_404_NOT_FOUND
            if isinstance(exc, NotFoundError)
            else status.HTTP_409_CONFLICT
        )

        raise HTTPException(
            status_code=status_code,
            detail=exc.message,
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception as exc:
        db.rollback()
        logger.exception(
            "Error permanently deleting scan %s: %s",
            scan_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan",
        )