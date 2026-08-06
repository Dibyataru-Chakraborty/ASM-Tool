"""Authenticated Recon Engine API backed by real scanner output."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import case
from sqlalchemy.orm import Session

from app.config import settings
from app.dependencies import get_current_user, require_tenant_member, require_org_admin
from app.models import AIServiceAssessment, Asset, Domain, Scan, Screenshot, Subdomain
from app.models.phase2 import Port, Service, Vulnerability
from app.services.discovery_service import DiscoveryService, get_live_scan_state
from app.services.recon_tool_service import inspect_chromium, inspect_recon_tools
from app.utils.database import SessionLocal, get_db


router = APIRouter(prefix="/recon", tags=["recon"])
REAL_RECON_SCAN_TYPE = "recon_full"


class ReconStartRequest(BaseModel):
    asset_id: str
    domain_id: Optional[str] = None
    confirmed_authorized: bool = False


class IPEnrichmentRequest(BaseModel):
    ip: str


def _hostname(value: str) -> Optional[str]:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    hostname = (parsed.hostname or "").rstrip(".")
    if not hostname:
        return None
    labels = hostname.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    return hostname


def _owned_domain(db: Session, user_id: str, domain_id: str) -> Domain:
    domain = (
        db.query(Domain)
        .join(Asset, Domain.asset_id == Asset.id)
        .filter(Domain.id == domain_id, Asset.organization_id == user_id)
        .first()
    )
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


def _has_verified_real_results(db: Session, domain: Domain) -> bool:
    """Keep legacy simulated rows hidden until a real Recon run completes."""
    return (
        db.query(Scan.id)
        .filter(
            Scan.asset_id == domain.asset_id,
            Scan.target_domain == domain.domain,
            Scan.scan_type == REAL_RECON_SCAN_TYPE,
            Scan.status == "completed",
        )
        .first()
        is not None
    )


def _run_recon_job(scan_id: str, domain_id: str) -> None:
    """Run a long scan in its own database session."""
    job_db = SessionLocal()
    try:
        DiscoveryService(job_db).run_real_scan(scan_id, domain_id)
    finally:
        job_db.close()


def _safe_json_list(value) -> list:
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


@router.get("/assets")
async def recon_assets(
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    """Return selectable owned targets and their internal IDs."""
    assets = (
        db.query(Asset)
        .filter(Asset.organization_id == current_user.current_organization_id, Asset.status == "active")
        .order_by(Asset.name.asc())
        .all()
    )
    items = []
    for asset in assets:
        if asset.asset_type not in {"domain", "subdomain", "url", "web_application", "organization"}:
            continue
        domains = db.query(Domain).filter(Domain.asset_id == asset.id).order_by(Domain.domain.asc()).all()
        fallback_domain = _hostname(asset.target or asset.name)
        if domains:
            for domain in domains:
                active_scan = (
                    db.query(Scan)
                    .filter(
                        Scan.asset_id == asset.id,
                        Scan.target_domain == domain.domain,
                        Scan.scan_type == REAL_RECON_SCAN_TYPE,
                        Scan.status.in_(("pending", "running")),
                    )
                    .order_by(Scan.created_at.desc())
                    .first()
                )
                items.append({
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "asset_type": asset.asset_type,
                    "target": asset.target or domain.domain,
                    "domain_id": domain.id,
                    "domain": domain.domain,
                    "scan_status": domain.scan_status,
                    "active_scan_id": active_scan.id if active_scan else None,
                })
        elif fallback_domain:
            items.append({
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_type": asset.asset_type,
                "target": asset.target or asset.name,
                "domain_id": None,
                "domain": fallback_domain,
                "scan_status": "not_scanned",
                "active_scan_id": None,
            })
    return {"items": items, "total": len(items)}


@router.get("/providers/status")
def provider_status(
    probe: bool = Query(True),
    current_user=Depends(require_tenant_member()),
):
    """Report every enabled scanner and optionally run safe startup probes."""
    tools = inspect_recon_tools(probe=probe, config=settings)
    chromium = inspect_chromium(probe=probe, config=settings)
    return {
        "ready": all(tool["available"] for tool in tools.values()) and chromium["available"],
        "probe_performed": probe,
        "projectdiscovery_tools": tools,
        "browser": {
            "chromium": chromium,
        },
        "ai_providers": {
            "gemini": {"configured": bool(settings.gemini_api_key)},
            "openai": {"configured": bool(settings.openai_api_key)},
            "claude": {"configured": bool(settings.claude_api_key)},
        },
        "threat_intelligence": {
            "virustotal": {"configured": bool(settings.virustotal_api_key)},
            "shodan": {"configured": bool(settings.shodan_api_key)},
            "abuseipdb": {"configured": bool(settings.abuseipdb_api_key)},
            "greynoise": {"configured": bool(settings.greynoise_api_key)},
        },
    }


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_recon(
    request: ReconStartRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(require_org_admin()),
    db: Session = Depends(get_db),
):
    if not request.confirmed_authorized:
        raise HTTPException(
            status_code=400,
            detail="Confirm that you own this target or have written permission to scan it",
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == request.asset_id, Asset.organization_id == current_user.current_organization_id, Asset.status == "active")
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if request.domain_id:
        domain = _owned_domain(db, current_user.current_organization_id, request.domain_id)
        if domain.asset_id != asset.id:
            raise HTTPException(status_code=400, detail="Domain does not belong to the selected asset")
    else:
        target = _hostname(asset.target or asset.name)
        if not target:
            raise HTTPException(
                status_code=422,
                detail="Recon requires a domain or URL asset with a valid hostname",
            )
        domain = db.query(Domain).filter(Domain.asset_id == asset.id, Domain.domain == target).first()
        if not domain:
            domain = DiscoveryService(db).create_domain(asset.id, target)

    service = DiscoveryService(db)
    scan = service.initiate_scan(asset.id, domain.id, REAL_RECON_SCAN_TYPE)
    background_tasks.add_task(_run_recon_job, scan.id, domain.id)
    return {
        "task_id": scan.id,
        "scan_reference": scan.reference_id,
        "asset_id": asset.id,
        "domain_id": domain.id,
        "domain": domain.domain,
        "status": scan.status,
    }


@router.get("/status/{scan_id}")
async def recon_status(
    scan_id: str,
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Scan.id == scan_id, Asset.organization_id == current_user.current_organization_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    domain = db.query(Domain).filter(
        Domain.asset_id == scan.asset_id,
        Domain.domain == scan.target_domain,
    ).first()
    live_state = get_live_scan_state(scan.id)
    live_subdomains = live_state.get("live_subdomains", [])
    return {
        "task_id": scan.id,
        "scan_reference": scan.reference_id,
        "status": scan.status,
        "asset_id": scan.asset_id,
        "domain_id": domain.id if domain else None,
        "domain": scan.target_domain,
        "summary": {
            "discoveries": max(scan.discovered_count or 0, len(live_subdomains)),
            "vulnerabilities": scan.vulnerable_count,
        },
        "current_tool": live_state.get("current_tool"),
        "progress": live_state.get(
            "progress",
            100 if scan.status in {"completed", "failed", "cancelled"} else 0,
        ),
        "live_subdomains": live_subdomains,
        "error": scan.error_message,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
    }


@router.get("/subdomains")
async def recon_subdomains(
    domain_id: str = Query(...),
    scan_id: Optional[str] = Query(None),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, current_user.current_organization_id, domain_id)
    live_names: list[str] = []
    live_scan = None
    if scan_id:
        live_scan = (
            db.query(Scan)
            .join(Asset, Scan.asset_id == Asset.id)
            .filter(
                Scan.id == scan_id,
                Scan.asset_id == domain.asset_id,
                Scan.target_domain == domain.domain,
                Scan.scan_type == REAL_RECON_SCAN_TYPE,
                Asset.organization_id == current_user.current_organization_id,
            )
            .first()
        )
        if not live_scan:
            raise HTTPException(status_code=404, detail="Scan not found for this domain")
        live_names = get_live_scan_state(scan_id).get("live_subdomains", [])

    if not live_scan and not _has_verified_real_results(db, domain):
        return {
            "subdomains": [],
            "total": 0,
            "verified_real_scan": False,
            "message": "Run and complete Full Recon to replace legacy unverified results.",
        }
    query = db.query(Subdomain).filter(Subdomain.domain_id == domain_id)
    if live_scan and live_scan.status != "completed":
        if not live_names:
            return {
                "subdomains": [],
                "total": 0,
                "live": live_scan.status in {"pending", "running"},
                "message": (
                    "Subfinder is running; discoveries will appear automatically."
                    if live_scan.status in {"pending", "running"}
                    else "This scan did not persist any subdomain discoveries."
                ),
            }
        query = query.filter(Subdomain.subdomain.in_(live_names))
    subdomains = query.order_by(Subdomain.subdomain).all()
    result = []
    for subdomain in subdomains:
        ports = (
            db.query(Port)
            .filter(Port.subdomain_id == subdomain.id, Port.status == "open")
            .order_by(Port.port_number)
            .all()
        )
        result.append({
            "id": subdomain.id,
            "subdomain": subdomain.subdomain,
            "ip_addresses": _safe_json_list(subdomain.ip_addresses),
            "open_ports": [port.port_number for port in ports],
            "services": [
                {
                    "id": service.id,
                    "port": port.port_number,
                    "protocol": port.protocol,
                    "name": service.service_name,
                    "product": service.product,
                    "version": service.version,
                    "confidence": service.confidence,
                }
                for port in ports
                for service in port.services
            ],
            "is_responsive": subdomain.is_responsive,
            "response_status_code": subdomain.response_status_code,
            "has_ssl": subdomain.has_ssl,
            "technologies": _safe_json_list(subdomain.technologies),
            "last_checked": subdomain.last_checked,
        })
    return {
        "subdomains": result,
        "total": len(result),
        "live": bool(live_scan and live_scan.status in {"pending", "running"}),
    }


@router.get("/ips")
async def recon_ips(
    domain_id: str = Query(...),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, current_user.current_organization_id, domain_id)
    if not _has_verified_real_results(db, domain):
        return {
            "ips": [],
            "total": 0,
            "verified_real_scan": False,
            "message": "Run and complete Full Recon to replace legacy unverified results.",
        }
    subdomains = db.query(Subdomain).filter(Subdomain.domain_id == domain_id).all()
    grouped: dict[str, set[str]] = {}
    for subdomain in subdomains:
        for address in _safe_json_list(subdomain.ip_addresses):
            grouped.setdefault(str(address), set()).add(subdomain.subdomain)
    result = [
        {"ip": address, "subdomains": sorted(names), "subdomain_count": len(names)}
        for address, names in sorted(grouped.items())
    ]
    return {"ips": result, "total": len(result)}


@router.get("/screenshots")
async def recon_screenshots(
    domain_id: str = Query(...),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, current_user.current_organization_id, domain_id)
    if not _has_verified_real_results(db, domain):
        return {
            "screenshots": [],
            "total": 0,
            "verified_real_scan": False,
            "message": "Run and complete Full Recon to replace legacy unverified results.",
        }
    rows = (
        db.query(Screenshot, Subdomain)
        .join(Subdomain, Screenshot.subdomain_id == Subdomain.id)
        .filter(Subdomain.domain_id == domain_id, Screenshot.is_valid == 1)
        .order_by(Screenshot.created_at.desc())
        .all()
    )
    screenshots = []
    for screenshot, subdomain in rows:
        relative_path = None
        if screenshot.file_path:
            try:
                relative_path = str(Path(screenshot.file_path).resolve().relative_to(Path("/app/screenshots").resolve()))
            except (ValueError, OSError):
                relative_path = Path(screenshot.file_path).name
        screenshots.append({
            "id": screenshot.id,
            "subdomain": subdomain.subdomain,
            "url": screenshot.url,
            "status_code": screenshot.status_code,
            "title": screenshot.title,
            "file_path": screenshot.file_path,
            "file_url": f"/screenshots/{relative_path.replace(os.sep, '/')}" if relative_path else None,
            "created_at": screenshot.created_at,
        })
    return {"screenshots": screenshots, "total": len(screenshots)}


@router.get("/vulnerabilities")
async def recon_vulnerabilities(
    domain_id: str = Query(...),
    scan_id: Optional[str] = Query(None),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, current_user.current_organization_id, domain_id)
    scan_query = db.query(Scan).filter(
        Scan.asset_id == domain.asset_id,
        Scan.target_domain == domain.domain,
    )
    if scan_id:
        scan = scan_query.filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for this domain")
    else:
        scan = (
            scan_query
            .filter(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .first()
        )

    if not scan:
        return {
            "vulnerabilities": [],
            "total": 0,
            "verified_real_scan": False,
            "message": "No completed real scan findings are available for this domain.",
        }

    severity_order = case(
        (Vulnerability.severity == "Critical", 0),
        (Vulnerability.severity == "High", 1),
        (Vulnerability.severity == "Medium", 2),
        (Vulnerability.severity == "Low", 3),
        else_=4,
    )
    rows = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .order_by(severity_order, Vulnerability.created_at.desc())
        .all()
    )
    vulnerabilities = [{
        "id": vulnerability.id,
        "scan_id": scan.id,
        "scan_reference": scan.reference_id,
        "cve_id": vulnerability.cve_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "subdomain": vulnerability.host or scan.target_domain or "unknown",
        "port": vulnerability.port,
        "source": vulnerability.source,
        "category": (
            "observation"
            if (vulnerability.severity or "Info").lower() == "info"
            else "vulnerability"
        ),
        "created_at": vulnerability.created_at,
    } for vulnerability in rows]
    actionable_total = sum(
        1 for vulnerability in rows
        if (vulnerability.severity or "Info").lower() != "info"
    )
    return {
        "vulnerabilities": vulnerabilities,
        "total": len(vulnerabilities),
        "actionable_total": actionable_total,
        "informational_total": len(vulnerabilities) - actionable_total,
        "verified_real_scan": scan.status == "completed",
        "scan_id": scan.id,
        "scan_reference": scan.reference_id,
    }


@router.get("/ai-service-assessments")
async def recon_ai_service_assessments(
    scan_id: str = Query(...),
    current_user=Depends(require_tenant_member()),
    db: Session = Depends(get_db),
):
    """Return grounded Gemini assessments for services from one owned scan."""
    scan = (
        db.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Scan.id == scan_id, Asset.organization_id == current_user.current_organization_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    rows = (
        db.query(AIServiceAssessment, Service, Port, Subdomain)
        .join(Service, AIServiceAssessment.service_id == Service.id)
        .join(Port, Service.port_id == Port.id)
        .join(Subdomain, Port.subdomain_id == Subdomain.id)
        .filter(AIServiceAssessment.scan_id == scan_id)
        .order_by(AIServiceAssessment.created_at.desc())
        .all()
    )
    assessments = []
    for assessment, service, port, subdomain in rows:
        assessments.append({
            "id": assessment.id,
            "scan_id": assessment.scan_id,
            "service_id": assessment.service_id,
            "provider": assessment.provider,
            "model_name": assessment.model_name,
            "lifecycle_status": assessment.lifecycle_status,
            "severity": assessment.severity,
            "title": assessment.title,
            "summary": assessment.summary,
            "detected_version": assessment.detected_version,
            "latest_version": assessment.latest_version,
            "cves": _safe_json_list(assessment.cves),
            "remediation": assessment.remediation,
            "confidence": assessment.confidence,
            "evidence_urls": _safe_json_list(assessment.evidence_urls),
            "host": subdomain.subdomain,
            "port": port.port_number,
            "protocol": port.protocol,
            "service_name": service.service_name,
            "product": service.product,
            "created_at": assessment.created_at,
        })
    return {"assessments": assessments, "total": len(assessments)}


@router.post("/enrich-ip")
async def enrich_ip(
    request: IPEnrichmentRequest,
    current_user=Depends(require_org_admin()),
):
    """Return factual local IP metadata; never synthesize reputation results."""
    try:
        address = ipaddress.ip_address(request.ip.strip())
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IPv4 or IPv6 address")
    try:
        reverse_dns = socket.gethostbyaddr(str(address))[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        reverse_dns = None
    return {
        "ip": str(address),
        "classification": {
            "version": address.version,
            "is_global": address.is_global,
            "is_private": address.is_private,
            "is_loopback": address.is_loopback,
            "is_multicast": address.is_multicast,
            "is_reserved": address.is_reserved,
        },
        "reverse_dns": reverse_dns,
        "reputation": {
            "status": "not_queried",
            "message": "Configure a threat-intelligence provider before requesting reputation data.",
        },
    }
