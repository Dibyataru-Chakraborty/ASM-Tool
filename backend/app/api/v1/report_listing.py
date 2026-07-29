"""Owner-scoped listing for persisted report records."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models import Asset, Domain, Report, Subdomain
from app.models.phase2 import Port, Service, Vulnerability
from app.utils.database import get_db


router = APIRouter(prefix="/reports", tags=["reports"])


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

