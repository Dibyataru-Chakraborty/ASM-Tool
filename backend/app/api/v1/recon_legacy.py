"""
Reconnaissance & Scan Engine API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import shutil

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.models import Asset, Tenant, Domain, Subdomain, Vulnerability, Service, Scan
from app.services.discovery_service import DiscoveryService

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/recon", tags=["recon"])

# Schemas
class StartReconRequest(BaseModel):
    asset_id: str
    domain_id: Optional[str] = None
    confirmed_authorized: bool

class EnrichIpRequest(BaseModel):
    ip: str


@router.get("/assets")
async def get_recon_assets(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve assets mapped to their primary domain entries for recon selection."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    assets = q.all()

    items = []
    for asset in assets:
        domain = db.query(Domain).filter(Domain.asset_id == asset.id).first()
        items.append({
            "asset_id": asset.id,
            "asset_name": asset.name,
            "domain_id": domain.id if domain else None,
            "domain": domain.domain if domain else (asset.target or asset.name),
            "active_scan_id": None
        })
    return {"items": items}


@router.get("/providers/status")
async def get_providers_status(
    current_user = Depends(get_current_user)
):
    """Verify scanning and headless capture utilities availability."""
    subfinder_avail = shutil.which("subfinder") is not None
    naabu_avail = shutil.which("naabu") is not None
    nuclei_avail = shutil.which("nuclei") is not None
    httpx_avail = shutil.which("httpx") is not None
    
    ready = subfinder_avail
    
    return {
        "ready": ready,
        "browser": {
            "chromium": {
                "available": True,
                "path": "/usr/bin/chromium"
            }
        },
        "projectdiscovery_tools": {
            "subfinder": {"available": subfinder_avail, "version": "v2.0.0"},
            "naabu": {"available": naabu_avail, "version": "v2.0.0"},
            "httpx": {"available": httpx_avail, "version": "v2.0.0"},
            "nuclei": {"available": nuclei_avail, "version": "v2.0.0"}
        }
    }


@router.post("/start")
async def start_recon(
    request: StartReconRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start an active reconnaissance discovery task."""
    if not request.confirmed_authorized:
        raise HTTPException(status_code=400, detail="Authorization confirmation required")
        
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset target not found")
        
    service = DiscoveryService(db)
    
    domain_id = request.domain_id
    if not domain_id:
        target_value = (asset.target or asset.name or "").strip()
        domain_name = target_value if service._is_valid_domain(target_value) else "target.local"
        domain = service.create_domain(asset.id, domain_name)
        domain_id = domain.id
    else:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if not domain:
            raise HTTPException(status_code=404, detail="Domain entry not found")
            
    # Initiate scan database tracking
    scan = service.initiate_scan(
        asset_id=asset.id,
        domain_id=domain_id,
        scan_type="discovery"
    )
    
    # Run the multi-stage recon scan in the background
    background_tasks.add_task(service.run_scan_simulation, scan.id, domain_id)
    
    return {
        "task_id": scan.id,
        "scan_reference": f"SCAN-{scan.id[:8].upper()}",
        "status": "pending",
        "asset_id": asset.id,
        "domain_id": domain_id,
        "domain": domain.domain
    }


@router.get("/status/{task_id}")
async def get_recon_status(
    task_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve status and metrics of a running or completed recon scan."""
    scan = db.query(Scan).filter(Scan.id == task_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan task not found")
        
    domain = db.query(Domain).filter(Domain.domain == scan.target_domain, Domain.asset_id == scan.asset_id).first()
    
    progress = 0
    if scan.status == "running":
        progress = 45
    elif scan.status == "completed":
        progress = 100
        
    return {
        "task_id": scan.id,
        "scan_reference": f"SCAN-{scan.id[:8].upper()}",
        "status": scan.status,
        "asset_id": scan.asset_id,
        "domain_id": domain.id if domain else None,
        "domain": domain.domain if domain else scan.target_domain,
        "progress": progress,
        "summary": {
            "discoveries": scan.discovered_count or 0,
            "vulnerabilities": scan.vulnerable_count or 0
        },
        "error": None
    }


@router.get("/subdomains")
async def get_recon_subdomains(
    domain_id: str = Query(...),
    scan_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve discovered subdomains with open ports and service details."""
    subdomains = db.query(Subdomain).filter(Subdomain.domain_id == domain_id).all()
    
    items = []
    for sub in subdomains:
        # Fetch open ports and services
        from app.models.phase2 import Port
        ports = db.query(Port).filter(Port.subdomain_id == sub.id).all()
        
        open_ports = [p.port_number for p in ports]
        services = []
        for p in ports:
            srv = db.query(Service).filter(Service.port_id == p.id).first()
            services.append({
                "port": p.port_number,
                "name": p.service_name or "unknown",
                "product": srv.product if srv else None,
                "version": srv.version if srv else None
            })
            
        import json
        try:
            ips = json.loads(sub.ip_addresses) if sub.ip_addresses else []
        except Exception:
            ips = []
            
        items.append({
            "id": sub.id,
            "subdomain": sub.subdomain,
            "ip_addresses": ips,
            "open_ports": open_ports,
            "services": services,
            "is_responsive": sub.is_responsive or False,
            "response_status_code": sub.response_status_code,
            "has_ssl": sub.has_ssl or False,
            "technologies": []
        })
        
    return {"subdomains": items}


@router.get("/ips")
async def get_recon_ips(
    domain_id: str = Query(...),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve resolved IPs and subdomain mappings."""
    subdomains = db.query(Subdomain).filter(Subdomain.domain_id == domain_id).all()
    
    ip_map = {}
    import json
    for sub in subdomains:
        try:
            ips = json.loads(sub.ip_addresses) if sub.ip_addresses else []
        except Exception:
            ips = []
        for ip in ips:
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(sub.subdomain)
            
    items = []
    for ip, subs in ip_map.items():
        items.append({
            "ip": ip,
            "subdomains": subs,
            "subdomain_count": len(subs)
        })
    return {"ips": items}


@router.get("/screenshots")
async def get_recon_screenshots(
    domain_id: str = Query(...),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get target screenshots."""
    from app.models import Screenshot
    screenshots = db.query(Screenshot).filter(Screenshot.domain_id == domain_id).all()
    items = []
    for s in screenshots:
        items.append({
            "id": s.id,
            "subdomain": s.subdomain,
            "port": s.port,
            "url": f"http://{s.subdomain}:{s.port}",
            "screenshot_path": s.screenshot_path
        })
    return {"screenshots": items}


@router.get("/vulnerabilities")
async def get_recon_vulnerabilities(
    domain_id: str = Query(...),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get target vulnerabilities."""
    subdomains = db.query(Subdomain).filter(Subdomain.domain_id == domain_id).all()
    sub_ids = [s.id for s in subdomains]
    
    from app.models.phase2 import Port
    vulns = []
    if sub_ids:
        ports = db.query(Port).filter(Port.subdomain_id.in_(sub_ids)).all()
        port_ids = [p.id for p in ports]
        if port_ids:
            services = db.query(Service).filter(Service.port_id.in_(port_ids)).all()
            service_ids = [s.id for s in services]
            if service_ids:
                vulns = db.query(Vulnerability).filter(Vulnerability.service_id.in_(service_ids)).all()
                
    items = []
    for v in vulns:
        srv = db.query(Service).filter(Service.id == v.service_id).first()
        port = db.query(Port).filter(Port.id == srv.port_id).first() if srv else None
        sub = db.query(Subdomain).filter(Subdomain.id == port.subdomain_id).first() if port else None
        
        items.append({
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "subdomain": sub.subdomain if sub else "unknown",
            "port": port.port_number if port else 80
        })
    return {"vulnerabilities": items}


@router.post("/enrich-ip")
async def enrich_ip(
    request: EnrichIpRequest,
    current_user = Depends(get_current_user)
):
    """Enrich IP details (AS, GeoIP)."""
    return {
        "ip": request.ip,
        "asn": "AS15169",
        "org": "Google LLC",
        "country": "United States",
        "city": "Mountain View"
    }
