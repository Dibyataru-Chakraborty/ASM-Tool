"""Durable, compact snapshots of terminal scan results.

PostgreSQL remains the canonical store. These gzip JSON snapshots freeze the
inventory that belonged to a particular scan so later scans cannot change an
older scan's detail view.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AIServiceAssessment,
    Asset,
    DNSRecord,
    Domain,
    Port,
    Scan,
    Screenshot,
    Service,
    Subdomain,
    Vulnerability,
)

logger = logging.getLogger(__name__)

TERMINAL_SCAN_STATUSES = {"completed", "failed", "cancelled"}
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _json_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _json_list(value: Any) -> list:
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


class ScanArchiveService:
    """Create, read, and explicitly delete compressed scan snapshots."""

    def __init__(self, root: Optional[str | Path] = None):
        self.root = Path(root or getattr(settings, "scan_archive_dir", "/app/scan_archives"))
        self.compression_level = max(
            1,
            min(9, int(getattr(settings, "scan_archive_compression_level", 9))),
        )

    @staticmethod
    def _safe_component(value: str) -> str:
        normalized = str(value or "")
        if not _SAFE_COMPONENT.fullmatch(normalized):
            raise ValueError("Invalid archive path component")
        return normalized

    def archive_path(self, user_id: str, scan_id: str) -> Path:
        return (
            self.root
            / self._safe_component(user_id)
            / f"{self._safe_component(scan_id)}.json.gz"
        )

    def write_payload(
        self,
        user_id: str,
        scan_id: str,
        payload: dict,
        *,
        overwrite: bool = False,
    ) -> Path:
        destination = self.archive_path(user_id, scan_id)
        if destination.is_file() and not overwrite:
            return destination

        destination.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=_json_value,
        ).encode("utf-8")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{scan_id}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as raw_file:
                with gzip.GzipFile(
                    fileobj=raw_file,
                    mode="wb",
                    compresslevel=self.compression_level,
                    mtime=0,
                ) as compressed:
                    compressed.write(encoded)
                raw_file.flush()
                os.fsync(raw_file.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return destination

    def read_archive(self, user_id: str, scan_id: str) -> Optional[dict]:
        archive = self.archive_path(user_id, scan_id)
        if not archive.is_file():
            return None
        with gzip.open(archive, "rt", encoding="utf-8") as source:
            payload = json.load(source)
        return payload if isinstance(payload, dict) else None

    def delete_archive(self, user_id: str, scan_id: str) -> bool:
        archive = self.archive_path(user_id, scan_id)
        if not archive.exists():
            return False
        archive.unlink()
        try:
            archive.parent.rmdir()
        except OSError:
            pass
        return True

    def archive_scan(
        self,
        db: Session,
        scan_id: str,
        *,
        overwrite: bool = False,
    ) -> Optional[Path]:
        scan_asset = (
            db.query(Scan, Asset)
            .join(Asset, Scan.asset_id == Asset.id)
            .filter(Scan.id == scan_id)
            .first()
        )
        if not scan_asset:
            return None
        scan, asset = scan_asset
        if str(scan.status).lower() not in TERMINAL_SCAN_STATUSES:
            return None

        destination = self.archive_path(asset.user_id, scan.id)
        if destination.is_file() and not overwrite:
            return destination

        domain = (
            db.query(Domain)
            .filter(
                Domain.asset_id == scan.asset_id,
                Domain.domain == scan.target_domain,
            )
            .first()
        )
        domain_id = domain.id if domain else None
        subdomains = (
            db.query(Subdomain)
            .filter(Subdomain.domain_id == domain_id)
            .order_by(Subdomain.subdomain)
            .all()
            if domain_id
            else []
        )
        subdomain_ids = [row.id for row in subdomains]

        ports = (
            db.query(Port)
            .filter(Port.subdomain_id.in_(subdomain_ids), Port.status == "open")
            .order_by(Port.port_number)
            .all()
            if subdomain_ids
            else []
        )
        ports_by_subdomain: dict[str, list[Port]] = {}
        for port in ports:
            ports_by_subdomain.setdefault(port.subdomain_id, []).append(port)

        services = (
            db.query(Service)
            .filter(Service.port_id.in_([row.id for row in ports]))
            .all()
            if ports
            else []
        )
        services_by_port: dict[str, list[Service]] = {}
        for service in services:
            services_by_port.setdefault(service.port_id, []).append(service)

        subdomain_payload = []
        grouped_ips: dict[str, set[str]] = {}
        for subdomain in subdomains:
            addresses = [str(value) for value in _json_list(subdomain.ip_addresses)]
            for address in addresses:
                grouped_ips.setdefault(address, set()).add(subdomain.subdomain)
            subdomain_ports = ports_by_subdomain.get(subdomain.id, [])
            subdomain_payload.append({
                "id": subdomain.id,
                "subdomain": subdomain.subdomain,
                "ip_addresses": addresses,
                "open_ports": [port.port_number for port in subdomain_ports],
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
                    for port in subdomain_ports
                    for service in services_by_port.get(port.id, [])
                ],
                "is_responsive": bool(subdomain.is_responsive),
                "response_status_code": subdomain.response_status_code,
                "has_ssl": bool(subdomain.has_ssl),
                "technologies": _json_list(subdomain.technologies),
                "last_checked": subdomain.last_checked,
            })

        vulnerabilities = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id)
            .order_by(Vulnerability.created_at.desc())
            .all()
        )
        vulnerability_payload = [{
            "id": row.id,
            "scan_id": scan.id,
            "scan_reference": scan.reference_id,
            "cve_id": row.cve_id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "cvss_score": row.cvss_score,
            "cvss_vector": row.cvss_vector,
            "subdomain": row.host or scan.target_domain or "unknown",
            "port": row.port,
            "matched_at": row.matched_at,
            "source": row.source,
            "category": (
                "observation"
                if (row.severity or "Info").lower() == "info"
                else "vulnerability"
            ),
            "created_at": row.created_at,
        } for row in vulnerabilities]

        assessment_rows = (
            db.query(AIServiceAssessment, Service, Port, Subdomain)
            .join(Service, AIServiceAssessment.service_id == Service.id)
            .join(Port, Service.port_id == Port.id)
            .join(Subdomain, Port.subdomain_id == Subdomain.id)
            .filter(AIServiceAssessment.scan_id == scan.id)
            .order_by(AIServiceAssessment.created_at.desc())
            .all()
        )
        assessment_payload = [{
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
            "cves": _json_list(assessment.cves),
            "remediation": assessment.remediation,
            "confidence": assessment.confidence,
            "evidence_urls": _json_list(assessment.evidence_urls),
            "host": subdomain.subdomain,
            "port": port.port_number,
            "protocol": port.protocol,
            "service_name": service.service_name,
            "product": service.product,
            "created_at": assessment.created_at,
        } for assessment, service, port, subdomain in assessment_rows]

        screenshot_rows = (
            db.query(Screenshot, Subdomain)
            .join(Subdomain, Screenshot.subdomain_id == Subdomain.id)
            .filter(Subdomain.domain_id == domain_id, Screenshot.is_valid == 1)
            .order_by(Screenshot.created_at.desc())
            .all()
            if domain_id
            else []
        )
        screenshot_payload = []
        screenshot_root = Path("/app/screenshots")
        for screenshot, subdomain in screenshot_rows:
            relative_path = None
            if screenshot.file_path:
                try:
                    relative_path = str(
                        Path(screenshot.file_path).resolve().relative_to(
                            screenshot_root.resolve()
                        )
                    )
                except (ValueError, OSError):
                    relative_path = Path(screenshot.file_path).name
            screenshot_payload.append({
                "id": screenshot.id,
                "subdomain": subdomain.subdomain,
                "url": screenshot.url,
                "status_code": screenshot.status_code,
                "title": screenshot.title,
                "file_url": (
                    f"/screenshots/{relative_path.replace(os.sep, '/')}"
                    if relative_path
                    else None
                ),
                "created_at": screenshot.created_at,
            })

        dns_rows = (
            db.query(DNSRecord)
            .filter(DNSRecord.domain_id == domain_id)
            .order_by(DNSRecord.record_type, DNSRecord.record_value)
            .all()
            if domain_id
            else []
        )

        payload = {
            "schema_version": 1,
            "archived_at": datetime.now(timezone.utc),
            "scan": {
                column.name: getattr(scan, column.name)
                for column in scan.__table__.columns
            },
            "asset": {
                "id": asset.id,
                "name": asset.name,
                "target": asset.target,
                "asset_type": asset.asset_type,
            },
            "domain": ({
                "id": domain.id,
                "domain": domain.domain,
                "registrar": domain.registrar,
                "expiration_date": domain.expiration_date,
                "is_vulnerable": bool(domain.is_vulnerable),
                "last_scanned": domain.last_scanned,
            } if domain else None),
            "domain_id": domain_id,
            "subdomains": subdomain_payload,
            "ips": [
                {
                    "ip": address,
                    "subdomains": sorted(names),
                    "subdomain_count": len(names),
                }
                for address, names in sorted(grouped_ips.items())
            ],
            "dns_records": [{
                "id": row.id,
                "record_type": row.record_type,
                "record_value": row.record_value,
                "ttl": row.ttl,
                "priority": row.priority,
                "weight": row.weight,
                "port": row.port,
            } for row in dns_rows],
            "vulnerabilities": vulnerability_payload,
            "ai_assessments": assessment_payload,
            "screenshots": screenshot_payload,
        }
        return self.write_payload(
            asset.user_id,
            scan.id,
            payload,
            overwrite=overwrite,
        )

    def backfill_missing(self, db: Session) -> int:
        scan_ids = [
            value
            for (value,) in db.query(Scan.id)
            .filter(Scan.status.in_(TERMINAL_SCAN_STATUSES))
            .order_by(Scan.created_at)
            .all()
        ]
        created = 0
        for scan_id in scan_ids:
            scan_asset = (
                db.query(Scan.id, Asset.user_id)
                .join(Asset, Scan.asset_id == Asset.id)
                .filter(Scan.id == scan_id)
                .first()
            )
            if not scan_asset:
                continue
            if self.archive_path(scan_asset.user_id, scan_id).is_file():
                continue
            try:
                if self.archive_scan(db, scan_id):
                    created += 1
            except Exception:
                logger.exception("Could not backfill scan archive %s", scan_id)
        return created
