"""Owner-scoped listing for persisted report records."""

from __future__ import annotations

import json
from io import BytesIO
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import case, or_
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models import Asset, Domain, Report, Scan, Subdomain
from app.models.phase2 import Port, Service, Vulnerability
from app.services.report_generation_service import (
    build_docx_report,
    build_pdf_report,
    build_scan_report_payload,
)
from app.utils.database import get_db


router = APIRouter(prefix="/reports", tags=["reports"])


class ScanReportRequest(BaseModel):
    """Scan reference supplied by a user from the scan history page."""

    scan_id: str = Field(min_length=1, max_length=64)


def _owned_scan(db: Session, user_id: str, scan_identifier: str) -> tuple[Scan, Asset]:
    row = (
        db.query(Scan, Asset)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(
            Asset.user_id == user_id,
            or_(
                Scan.id == scan_identifier.strip(),
                Scan.reference_id == scan_identifier.strip(),
            ),
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Scan ID was not found")
    scan, asset = row
    if str(scan.status).lower() in {"pending", "queued", "running"}:
        raise HTTPException(
            status_code=409,
            detail="This scan is still running. Generate the report after it completes.",
        )
    return scan, asset


def _scan_report(db: Session, user_id: str, scan_identifier: str) -> dict:
    scan, asset = _owned_scan(db, user_id, scan_identifier)
    severity_order = case(
        (Vulnerability.severity == "Critical", 0),
        (Vulnerability.severity == "High", 1),
        (Vulnerability.severity == "Medium", 2),
        (Vulnerability.severity == "Low", 3),
        else_=4,
    )
    findings = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .order_by(severity_order, Vulnerability.cvss_score.desc().nullslast(), Vulnerability.id)
        .all()
    )
    return build_scan_report_payload(scan, asset, findings)


@router.post("/generate")
async def generate_scan_report(
    request: ScanReportRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Build a structured report from findings retained under one scan ID."""
    return _scan_report(db, current_user.id, request.scan_id)


@router.get("/scan/{scan_identifier}/export/{report_format}")
async def export_scan_report(
    scan_identifier: str,
    report_format: Literal["docx", "pdf"],
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download the scan-scoped structured report as Word or PDF."""
    report = _scan_report(db, current_user.id, scan_identifier)
    reference = report["scan"]["reference_id"]
    if report_format == "docx":
        content = build_docx_report(report)
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        content = build_pdf_report(report)
        media_type = "application/pdf"
    filename = f"security-report-{reference}.{report_format}"
    return StreamingResponse(
        BytesIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
async def list_reports(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return real report rows and summaries from stored findings."""
    rows = (
        db.query(Report, Asset)
        .join(Asset, Report.asset_id == Asset.id)
        .filter(Asset.user_id == current_user.id)
        .order_by(Report.created_at.desc())
        .all()
    )
    reports = []
    for report, asset in rows:
        vulnerabilities = (
            db.query(Vulnerability)
            .join(Service, Vulnerability.service_id == Service.id)
            .join(Port, Service.port_id == Port.id)
            .join(Subdomain, Port.subdomain_id == Subdomain.id)
            .join(Domain, Subdomain.domain_id == Domain.id)
            .filter(Domain.asset_id == asset.id)
            .all()
        )
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        max_score = 0.0
        for vulnerability in vulnerabilities:
            severity = (vulnerability.severity or "").capitalize()
            if severity in counts:
                counts[severity] += 1
            if vulnerability.cvss_score is not None:
                max_score = max(max_score, float(vulnerability.cvss_score))

        technologies: set[str] = set()
        technology_rows = (
            db.query(Subdomain.technologies)
            .join(Domain, Subdomain.domain_id == Domain.id)
            .filter(Domain.asset_id == asset.id)
            .all()
        )
        for raw_technologies, in technology_rows:
            try:
                values = json.loads(raw_technologies or "[]")
                if isinstance(values, list):
                    technologies.update(str(value) for value in values)
            except (TypeError, ValueError):
                continue

        if max_score >= 9:
            risk_rating = "Critical"
        elif max_score >= 7:
            risk_rating = "High"
        elif max_score >= 4:
            risk_rating = "Medium"
        elif max_score > 0:
            risk_rating = "Low"
        else:
            risk_rating = "Informational"

        reports.append({
            "id": report.id,
            "asset_id": report.asset_id,
            "asset_name": asset.name,
            "title": report.title,
            "report_type": report.report_type,
            "format": report.format,
            "status": report.status,
            "generated_at": report.created_at,
            "risk_rating": risk_rating,
            "risk_score": max_score,
            "critical_count": counts["Critical"],
            "high_count": counts["High"],
            "medium_count": counts["Medium"],
            "low_count": counts["Low"],
            "total_vulns": len(vulnerabilities),
            "technologies": sorted(technologies),
        })

    return {"reports": reports, "total": len(reports)}
