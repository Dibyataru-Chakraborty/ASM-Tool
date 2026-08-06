"""Attack Surface Management inventory synchronization and query helpers.

The recon engine remains the collection layer. This service converts each completed
scan into a persistent, organization-centric inventory so later scans can detect
new, changed, removed and reappearing internet-facing assets.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models import (
    Alert,
    Asset,
    Organization,
    AssetChange,
    AssetObservation,
    AssetRelationship,
    DiscoverySeed,
    DiscoveredAsset,
    Domain,
    Exposure,
    Scan,
    SSLCertificate,
    Subdomain,
)
from app.models.phase2 import Port, Vulnerability


SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "medium"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    135: ("RPC", "high"),
    139: ("NetBIOS", "high"),
    445: ("SMB", "high"),
    1433: ("Microsoft SQL Server", "high"),
    1521: ("Oracle Database", "high"),
    2375: ("Docker API", "critical"),
    3306: ("MySQL", "high"),
    3389: ("Remote Desktop", "high"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"),
    27017: ("MongoDB", "high"),
}

SEVERITY_BASE = {
    "critical": 85,
    "high": 70,
    "medium": 50,
    "low": 25,
    "info": 10,
    "informational": 10,
}


class AttackSurfaceService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
        """Normalize DB timestamps for safe comparisons across DB backends."""
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))

    @staticmethod
    def _json_list(value: Any) -> list[Any]:
        if not value:
            return []
        if isinstance(value, list):
            return value
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError, json.JSONDecodeError):
            return []

    @classmethod
    def _state_hash(cls, payload: dict[str, Any]) -> str:
        return hashlib.sha256(cls._json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _severity(value: Optional[str]) -> str:
        normalized = (value or "info").strip().lower()
        if normalized == "informational":
            return "info"
        return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info"

    @classmethod
    def _exposure_fingerprint(cls, *parts: Any) -> str:
        raw = "|".join(str(part or "").strip().lower() for part in parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _organization(self, organization_id: str) -> Organization:
        organization = self.db.query(Organization).filter(Organization.id == organization_id).first()
        if not organization:
            raise ValueError("Organization not found")
        return organization

    def ensure_primary_seed(self, organization_id: str, domain: Optional[Domain] = None) -> None:
        organization = self._organization(organization_id)
        value = (domain.domain if domain else "").strip().lower()
        if not value:
            return
        seed = self.db.query(DiscoverySeed).filter(
            DiscoverySeed.organization_id == organization.id,
            DiscoverySeed.seed_type == "domain",
            DiscoverySeed.value == value,
        ).first()
        primary_exists = self.db.query(DiscoverySeed.id).filter(
            DiscoverySeed.organization_id == organization.id,
            DiscoverySeed.is_primary.is_(True),
            DiscoverySeed.is_active.is_(True),
        ).first() is not None
        if seed:
            # Keep one canonical primary seed. Additional confirmed domains remain
            # approved seeds but do not silently replace the tenant's primary root.
            if not primary_exists:
                seed.is_primary = True
            seed.is_active = True
            seed.ownership_status = "confirmed"
            seed.confidence_score = 1.0
            return
        self.db.add(
            DiscoverySeed(
                organization_id=organization.id,
                seed_type="domain",
                value=value,
                is_primary=not primary_exists,
                is_active=True,
                ownership_status="confirmed",
                confidence_score=1.0,
            )
        )

    def _record_change(
        self,
        organization_id: str,
        discovered_asset: Optional[DiscoveredAsset],
        scan_id: Optional[str],
        change_type: str,
        title: str,
        *,
        severity: str = "info",
        details: Optional[dict[str, Any]] = None,
        detected_at: Optional[datetime] = None,
    ) -> AssetChange:
        row = AssetChange(
            organization_id=organization_id,
            discovered_asset_id=discovered_asset.id if discovered_asset else None,
            scan_id=scan_id,
            change_type=change_type,
            severity=self._severity(severity),
            title=title[:255],
            details_json=self._json(details or {}),
            detected_at=detected_at or self._now(),
            is_acknowledged=False,
        )
        self.db.add(row)
        return row

    def _upsert_asset(
        self,
        *,
        organization_id: str,
        scope_domain_id: Optional[str],
        scan_id: str,
        asset_type: str,
        value: str,
        metadata: dict[str, Any],
        display_name: Optional[str] = None,
        ownership_status: str = "high_confidence",
        confidence_score: float = 0.9,
        internet_exposed: bool = True,
        now: datetime,
    ) -> tuple[DiscoveredAsset, bool, bool]:
        normalized_value = str(value or "").strip()
        if asset_type in {"domain", "subdomain", "candidate_domain", "ip"}:
            normalized_value = normalized_value.lower()
        if not normalized_value:
            raise ValueError("Cannot persist an empty attack-surface asset")

        state_hash = self._state_hash(metadata)
        row = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.organization_id == organization_id,
            DiscoveredAsset.asset_type == asset_type,
            DiscoveredAsset.value == normalized_value,
        ).first()

        is_new = row is None
        is_changed = False
        previous_status = None
        previous_hash = None
        if row is None:
            row = DiscoveredAsset(
                organization_id=organization_id,
                scope_domain_id=scope_domain_id,
                asset_type=asset_type,
                value=normalized_value,
                display_name=display_name or normalized_value,
                status="new",
                ownership_status=ownership_status,
                confidence_score=confidence_score,
                criticality="normal",
                internet_exposed=internet_exposed,
                risk_score=0,
                first_seen=now,
                last_seen=now,
                first_seen_scan_id=scan_id,
                last_seen_scan_id=scan_id,
                metadata_json=self._json(metadata),
                state_hash=state_hash,
            )
            self.db.add(row)
            self.db.flush()
            severity = "medium" if ownership_status == "requires_investigation" else "low"
            self._record_change(
                organization_id,
                row,
                scan_id,
                "new_asset",
                f"New {asset_type.replace('_', ' ')} discovered: {display_name or normalized_value}",
                severity=severity,
                details={"asset_type": asset_type, "value": normalized_value},
                detected_at=now,
            )
        else:
            previous_status = row.status
            previous_hash = row.state_hash
            row.scope_domain_id = scope_domain_id or row.scope_domain_id
            row.display_name = display_name or row.display_name or normalized_value
            row.last_seen = now
            row.last_seen_scan_id = scan_id
            row.internet_exposed = internet_exposed
            # Never silently downgrade a user's ownership decision.
            if row.ownership_status not in {"confirmed", "rejected"}:
                row.ownership_status = ownership_status
                row.confidence_score = max(row.confidence_score or 0.0, confidence_score)
            if previous_status in {"inactive", "historical"}:
                is_changed = True
                row.status = "changed"
                self._record_change(
                    organization_id,
                    row,
                    scan_id,
                    "reactivated_asset",
                    f"Asset reappeared: {row.display_name or row.value}",
                    severity="medium",
                    detected_at=now,
                )
            elif previous_hash and previous_hash != state_hash:
                is_changed = True
                row.status = "changed"
                self._record_change(
                    organization_id,
                    row,
                    scan_id,
                    "asset_changed",
                    f"Asset changed: {row.display_name or row.value}",
                    severity="low",
                    details={"previous_state_hash": previous_hash, "current_state_hash": state_hash},
                    detected_at=now,
                )
            else:
                row.status = "active"
            row.metadata_json = self._json(metadata)
            row.state_hash = state_hash

        observation = self.db.query(AssetObservation).filter(
            AssetObservation.discovered_asset_id == row.id,
            AssetObservation.scan_id == scan_id,
        ).first()
        if not observation:
            self.db.add(
                AssetObservation(
                    organization_id=organization_id,
                    discovered_asset_id=row.id,
                    scan_id=scan_id,
                    observed_at=now,
                    state_hash=state_hash,
                    snapshot_json=self._json(metadata),
                )
            )
        return row, is_new, is_changed

    def _upsert_relationship(
        self,
        *,
        organization_id: str,
        source_asset: DiscoveredAsset,
        target_asset: DiscoveredAsset,
        relationship_type: str,
        now: datetime,
        confidence_score: float = 1.0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AssetRelationship:
        row = self.db.query(AssetRelationship).filter(
            AssetRelationship.organization_id == organization_id,
            AssetRelationship.source_asset_id == source_asset.id,
            AssetRelationship.target_asset_id == target_asset.id,
            AssetRelationship.relationship_type == relationship_type,
        ).first()
        if not row:
            row = AssetRelationship(
                organization_id=organization_id,
                source_asset_id=source_asset.id,
                target_asset_id=target_asset.id,
                relationship_type=relationship_type,
                confidence_score=confidence_score,
                is_active=True,
                first_seen=now,
                last_seen=now,
                metadata_json=self._json(metadata or {}),
            )
            self.db.add(row)
            self.db.flush()
        else:
            row.is_active = True
            row.last_seen = now
            row.confidence_score = max(row.confidence_score or 0.0, confidence_score)
            row.metadata_json = self._json(metadata or {})
        return row

    def _risk_score(self, severity: str, criticality: str, internet_exposed: bool) -> int:
        score = SEVERITY_BASE.get(self._severity(severity), 10)
        if internet_exposed:
            score += 5
        if criticality == "critical":
            score += 10
        elif criticality == "high":
            score += 5
        return min(100, score)

    def _upsert_exposure(
        self,
        *,
        organization_id: str,
        discovered_asset: Optional[DiscoveredAsset],
        scan_id: str,
        fingerprint: str,
        exposure_type: str,
        title: str,
        severity: str,
        now: datetime,
        cvss_score: Optional[float] = None,
        cve_id: Optional[str] = None,
        source_vulnerability_id: Optional[str] = None,
        exploitability: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> Exposure:
        severity = self._severity(severity)
        row = self.db.query(Exposure).filter(
            Exposure.organization_id == organization_id,
            Exposure.fingerprint == fingerprint,
        ).first()
        is_new = row is None
        criticality = discovered_asset.criticality if discovered_asset else "normal"
        risk_score = self._risk_score(severity, criticality, True)
        if row is None:
            row = Exposure(
                organization_id=organization_id,
                discovered_asset_id=discovered_asset.id if discovered_asset else None,
                scan_id=scan_id,
                source_vulnerability_id=source_vulnerability_id,
                fingerprint=fingerprint,
                exposure_type=exposure_type,
                title=title[:255],
                severity=severity,
                risk_score=risk_score,
                cvss_score=cvss_score,
                cve_id=cve_id,
                internet_exposed=True,
                exploitability=exploitability,
                status="open",
                first_seen=now,
                last_seen=now,
                resolved_at=None,
                details_json=self._json(details or {}),
            )
            self.db.add(row)
            self.db.flush()
        else:
            row.discovered_asset_id = discovered_asset.id if discovered_asset else row.discovered_asset_id
            row.scan_id = scan_id
            row.source_vulnerability_id = source_vulnerability_id or row.source_vulnerability_id
            row.title = title[:255]
            row.severity = severity
            row.risk_score = risk_score
            row.cvss_score = cvss_score
            row.cve_id = cve_id
            row.exploitability = exploitability
            if row.status not in {"accepted_risk", "false_positive", "in_progress"}:
                row.status = "open"
                row.resolved_at = None
            row.last_seen = now
            row.details_json = self._json(details or {})

        if discovered_asset:
            discovered_asset.risk_score = max(discovered_asset.risk_score or 0, risk_score)

        if is_new:
            self._record_change(
                organization_id,
                discovered_asset,
                scan_id,
                "new_exposure",
                f"New {severity} exposure: {title}",
                severity=severity,
                details={"exposure_type": exposure_type, "risk_score": risk_score},
                detected_at=now,
            )
            if severity in {"critical", "high"}:
                alert_scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
                if alert_scan:
                    self.db.add(
                        Alert(
                        asset_id=alert_scan.asset_id,
                        alert_type="NewExposure",
                        severity=severity.capitalize(),
                        message=f"{title} (ASM risk {risk_score}/100)",
                        is_resolved=False,
                        notification_channels="dashboard",
                    )
                )
        return row

    def sync_from_scan(self, scan_id: str, domain_id: str) -> dict[str, int]:
        """Convert one completed recon scan into a persistent ASM state."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        domain = self.db.query(Domain).filter(Domain.id == domain_id).first()
        if not scan or not domain or domain.asset_id != scan.asset_id:
            raise ValueError("Cannot synchronize an unknown scan target")

        asset = self.db.query(Asset).filter(Asset.id == scan.asset_id).first()
        if not asset or domain.organization_id != asset.organization_id:
            raise ValueError("Cannot synchronize a scan outside its organization")
        organization = self._organization(asset.organization_id)
        now = self._now()
        self.ensure_primary_seed(organization.id, domain)
        self.db.flush()

        seen_asset_ids: set[str] = set()
        seen_relationship_ids: set[str] = set()
        seen_exposure_fingerprints: set[str] = set()
        by_host: dict[str, DiscoveredAsset] = {}
        by_ip: dict[str, DiscoveredAsset] = {}
        by_service_key: dict[tuple[str, int, str], DiscoveredAsset] = {}

        root, _, _ = self._upsert_asset(
            organization_id=organization.id,
            scope_domain_id=domain.id,
            scan_id=scan.id,
            asset_type="domain",
            value=domain.domain,
            display_name=domain.domain,
            metadata={
                "domain": domain.domain,
                "registrar": domain.registrar,
                "expiration_date": domain.expiration_date,
                "is_vulnerable": bool(domain.is_vulnerable),
            },
            ownership_status="confirmed",
            confidence_score=1.0,
            now=now,
        )
        seen_asset_ids.add(root.id)
        by_host[domain.domain.lower()] = root

        subdomains = self.db.query(Subdomain).filter(Subdomain.domain_id == domain.id).all()
        for subdomain in subdomains:
            host = subdomain.subdomain.lower()
            ips = sorted({str(ip).strip() for ip in self._json_list(subdomain.ip_addresses) if str(ip).strip()})
            technologies = sorted({str(x).strip() for x in self._json_list(subdomain.technologies) if str(x).strip()})
            host_asset, _, _ = self._upsert_asset(
                organization_id=organization.id,
                scope_domain_id=domain.id,
                scan_id=scan.id,
                asset_type="subdomain",
                value=host,
                display_name=host,
                metadata={
                    "ip_addresses": ips,
                    "responsive": bool(subdomain.is_responsive),
                    "status_code": subdomain.response_status_code,
                    "has_ssl": bool(subdomain.has_ssl),
                    "ssl_grade": subdomain.ssl_grade,
                    "technologies": technologies,
                },
                ownership_status="confirmed" if host == domain.domain.lower() else "high_confidence",
                confidence_score=1.0 if host == domain.domain.lower() else 0.98,
                now=now,
            )
            seen_asset_ids.add(host_asset.id)
            by_host[host] = host_asset
            if host_asset.id != root.id:
                link = self._upsert_relationship(
                    organization_id=organization.id,
                    source_asset=root,
                    target_asset=host_asset,
                    relationship_type="DOMAIN_HAS_SUBDOMAIN",
                    now=now,
                    confidence_score=1.0,
                )
                seen_relationship_ids.add(link.id)

            for ip in ips:
                ip_asset, _, _ = self._upsert_asset(
                    organization_id=organization.id,
                    scope_domain_id=domain.id,
                    scan_id=scan.id,
                    asset_type="ip",
                    value=ip,
                    display_name=ip,
                    metadata={"ip": ip},
                    ownership_status="high_confidence",
                    confidence_score=0.95,
                    now=now,
                )
                seen_asset_ids.add(ip_asset.id)
                by_ip[ip] = ip_asset
                link = self._upsert_relationship(
                    organization_id=organization.id,
                    source_asset=host_asset,
                    target_asset=ip_asset,
                    relationship_type="HOST_RESOLVES_TO_IP",
                    now=now,
                    confidence_score=1.0,
                )
                seen_relationship_ids.add(link.id)

            ports = self.db.query(Port).filter(
                Port.subdomain_id == subdomain.id,
                Port.status == "open",
            ).all()
            for port in ports:
                service = port.services[0] if port.services else None
                protocol = (port.protocol or "tcp").lower()
                service_name = (
                    (service.service_name if service else None)
                    or port.service_name
                    or "unknown"
                )
                service_value = f"{host}:{port.port_number}/{protocol}"
                service_asset, _, _ = self._upsert_asset(
                    organization_id=organization.id,
                    scope_domain_id=domain.id,
                    scan_id=scan.id,
                    asset_type="service",
                    value=service_value,
                    display_name=f"{host}:{port.port_number} {service_name}",
                    metadata={
                        "host": host,
                        "port": port.port_number,
                        "protocol": protocol,
                        "service": service_name,
                        "product": service.product if service else None,
                        "version": service.version if service else None,
                        "confidence": service.confidence if service else None,
                    },
                    ownership_status="high_confidence",
                    confidence_score=0.95,
                    now=now,
                )
                seen_asset_ids.add(service_asset.id)
                by_service_key[(host, port.port_number, protocol)] = service_asset
                link = self._upsert_relationship(
                    organization_id=organization.id,
                    source_asset=host_asset,
                    target_asset=service_asset,
                    relationship_type="HOST_EXPOSES_SERVICE",
                    now=now,
                    confidence_score=1.0,
                )
                seen_relationship_ids.add(link.id)
                for ip in ips:
                    ip_asset = by_ip.get(ip)
                    if ip_asset:
                        ip_link = self._upsert_relationship(
                            organization_id=organization.id,
                            source_asset=ip_asset,
                            target_asset=service_asset,
                            relationship_type="IP_EXPOSES_SERVICE",
                            now=now,
                            confidence_score=0.95,
                        )
                        seen_relationship_ids.add(ip_link.id)

                if port.port_number in SENSITIVE_PORTS:
                    label, severity = SENSITIVE_PORTS[port.port_number]
                    fp = self._exposure_fingerprint(
                        "exposed_service", host, port.port_number, protocol
                    )
                    seen_exposure_fingerprints.add(fp)
                    self._upsert_exposure(
                        organization_id=organization.id,
                        discovered_asset=service_asset,
                        scan_id=scan.id,
                        fingerprint=fp,
                        exposure_type="exposed_service",
                        title=f"Internet-facing {label} service on {host}:{port.port_number}",
                        severity=severity,
                        now=now,
                        exploitability="configuration_dependent",
                        details={
                            "host": host,
                            "port": port.port_number,
                            "protocol": protocol,
                            "service": service_name,
                        },
                    )

        certificates = self.db.query(SSLCertificate).filter(SSLCertificate.domain_id == domain.id).all()
        for cert in certificates:
            cert_key = cert.fingerprint_sha256 or f"{cert.certificate_subject}|{cert.issuer}|{cert.valid_to}"
            cert_asset, _, _ = self._upsert_asset(
                organization_id=organization.id,
                scope_domain_id=domain.id,
                scan_id=scan.id,
                asset_type="certificate",
                value=cert_key,
                display_name=cert.certificate_subject,
                metadata={
                    "subject": cert.certificate_subject,
                    "issuer": cert.issuer,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                    "is_valid": bool(cert.is_valid),
                    "is_expired": bool(cert.is_expired),
                    "is_self_signed": bool(cert.is_self_signed),
                    "is_trusted": bool(cert.is_trusted),
                    "ssl_grade": cert.ssl_grade,
                },
                ownership_status="high_confidence",
                confidence_score=0.95,
                now=now,
            )
            seen_asset_ids.add(cert_asset.id)
            parent = by_host.get(cert.subdomain.subdomain.lower()) if cert.subdomain else root
            if parent:
                link = self._upsert_relationship(
                    organization_id=organization.id,
                    source_asset=parent,
                    target_asset=cert_asset,
                    relationship_type="HOST_USES_CERTIFICATE",
                    now=now,
                    confidence_score=1.0,
                )
                seen_relationship_ids.add(link.id)

            valid_to = cert.valid_to
            if valid_to and valid_to.tzinfo is None:
                valid_to = valid_to.replace(tzinfo=timezone.utc)
            days_left = int((valid_to - now).total_seconds() // 86400) if valid_to else None
            if cert.is_expired or not cert.is_valid or (days_left is not None and days_left <= 30):
                if cert.is_expired:
                    severity = "high"
                    title = f"Expired TLS certificate: {cert.certificate_subject}"
                    issue = "expired"
                elif not cert.is_valid:
                    severity = "high"
                    title = f"Invalid TLS certificate: {cert.certificate_subject}"
                    issue = "invalid"
                else:
                    severity = "medium" if (days_left or 0) <= 14 else "low"
                    title = f"TLS certificate expires in {days_left} days: {cert.certificate_subject}"
                    issue = "expiring"
                fp = self._exposure_fingerprint("certificate", cert_key, issue)
                seen_exposure_fingerprints.add(fp)
                self._upsert_exposure(
                    organization_id=organization.id,
                    discovered_asset=cert_asset,
                    scan_id=scan.id,
                    fingerprint=fp,
                    exposure_type="certificate_issue",
                    title=title,
                    severity=severity,
                    now=now,
                    exploitability="not_applicable",
                    details={"issue": issue, "days_remaining": days_left},
                )

            # SANs outside the approved root are candidates only; they are never
            # automatically scanned or claimed as company-owned assets.
            for san in self._json_list(cert.certificate_subject_alt_names):
                candidate = str(san or "").strip().lower().lstrip("*.")
                if not candidate or candidate == domain.domain.lower() or candidate.endswith(f".{domain.domain.lower()}"):
                    continue
                candidate_asset, _, _ = self._upsert_asset(
                    organization_id=organization.id,
                    scope_domain_id=domain.id,
                    scan_id=scan.id,
                    asset_type="candidate_domain",
                    value=candidate,
                    display_name=candidate,
                    metadata={"discovered_via": "certificate_san", "certificate": cert.certificate_subject},
                    ownership_status="requires_investigation",
                    confidence_score=0.55,
                    now=now,
                )
                seen_asset_ids.add(candidate_asset.id)
                link = self._upsert_relationship(
                    organization_id=organization.id,
                    source_asset=cert_asset,
                    target_asset=candidate_asset,
                    relationship_type="CERTIFICATE_REFERENCES_DOMAIN",
                    now=now,
                    confidence_score=0.55,
                )
                seen_relationship_ids.add(link.id)

        vulnerabilities = self.db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id,
            Vulnerability.is_false_positive.is_(False),
        ).all()
        for vulnerability in vulnerabilities:
            host = (vulnerability.host or domain.domain).strip().lower()
            discovered_asset = None
            if vulnerability.port is not None:
                discovered_asset = by_service_key.get((host, vulnerability.port, "tcp"))
                if not discovered_asset:
                    # Protocol may be unavailable on the finding. Fall back to any
                    # service asset on the same host/port.
                    discovered_asset = next(
                        (
                            asset
                            for (h, p, _proto), asset in by_service_key.items()
                            if h == host and p == vulnerability.port
                        ),
                        None,
                    )
            discovered_asset = discovered_asset or by_host.get(host) or root
            fp = self._exposure_fingerprint(
                "vulnerability",
                vulnerability.cve_id,
                vulnerability.title,
                host,
                vulnerability.port,
            )
            seen_exposure_fingerprints.add(fp)
            self._upsert_exposure(
                organization_id=organization.id,
                discovered_asset=discovered_asset,
                scan_id=scan.id,
                fingerprint=fp,
                exposure_type="vulnerability",
                title=vulnerability.title,
                severity=vulnerability.severity or "info",
                now=now,
                cvss_score=vulnerability.cvss_score,
                cve_id=vulnerability.cve_id,
                source_vulnerability_id=vulnerability.id,
                exploitability="unknown",
                details={
                    "host": host,
                    "port": vulnerability.port,
                    "matched_at": vulnerability.matched_at,
                    "source": vulnerability.source,
                    "description": vulnerability.description,
                },
            )

        # Anything in this domain scope that was previously visible but is no
        # longer present becomes inactive instead of being deleted.
        missing_assets = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.organization_id == organization.id,
            DiscoveredAsset.scope_domain_id == domain.id,
            DiscoveredAsset.status.in_(["new", "active", "changed"]),
            ~DiscoveredAsset.id.in_(seen_asset_ids) if seen_asset_ids else True,
        ).all()
        for row in missing_assets:
            row.status = "inactive"
            self._record_change(
                organization.id,
                row,
                scan.id,
                "asset_removed",
                f"Asset no longer observed: {row.display_name or row.value}",
                severity="info",
                detected_at=now,
            )

        relationships = self.db.query(AssetRelationship).join(
            DiscoveredAsset,
            AssetRelationship.source_asset_id == DiscoveredAsset.id,
        ).filter(
            AssetRelationship.organization_id == organization.id,
            DiscoveredAsset.scope_domain_id == domain.id,
            AssetRelationship.is_active.is_(True),
        ).all()
        for relationship in relationships:
            if relationship.id not in seen_relationship_ids:
                relationship.is_active = False

        scoped_asset_ids = [
            row.id
            for row in self.db.query(DiscoveredAsset.id).filter(
                DiscoveredAsset.organization_id == organization.id,
                DiscoveredAsset.scope_domain_id == domain.id,
            ).all()
        ]
        if scoped_asset_ids:
            stale_exposures = self.db.query(Exposure).filter(
                Exposure.organization_id == organization.id,
                Exposure.discovered_asset_id.in_(scoped_asset_ids),
                Exposure.status.in_(["open", "in_progress"]),
                ~Exposure.fingerprint.in_(seen_exposure_fingerprints) if seen_exposure_fingerprints else True,
            ).all()
            for exposure in stale_exposures:
                exposure.status = "resolved"
                exposure.resolved_at = now
                self._record_change(
                    organization.id,
                    self.db.query(DiscoveredAsset).filter(DiscoveredAsset.id == exposure.discovered_asset_id).first(),
                    scan.id,
                    "exposure_resolved",
                    f"Exposure no longer observed: {exposure.title}",
                    severity="info",
                    detected_at=now,
                )

        # Recalculate each inventory asset from currently open exposures.
        rows = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.organization_id == organization.id
        ).all()
        for row in rows:
            max_risk = self.db.query(func.max(Exposure.risk_score)).filter(
                Exposure.discovered_asset_id == row.id,
                Exposure.status.in_(["open", "in_progress"]),
            ).scalar()
            row.risk_score = int(max_risk or 0)

        open_scores = [row.risk_score for row in rows if row.status != "inactive"]
        root_asset = self.db.query(Asset).filter(Asset.id == scan.asset_id).first()
        if root_asset:
            root_asset.risk_score = max(open_scores, default=0)
        self.db.commit()
        return {
            "inventory_assets": len(seen_asset_ids),
            "relationships": len(seen_relationship_ids),
            "open_exposures": len(seen_exposure_fingerprints),
            "removed_assets": len(missing_assets),
        }

    def overview(self, organization_scope: Optional[str], organization_id: Optional[str] = None) -> dict[str, Any]:
        selected = organization_id or organization_scope
        org_query = self.db.query(Organization.id).filter(Organization.status == "active")
        if selected:
            org_query = org_query.filter(Organization.id == selected)
        org_ids = [row[0] for row in org_query.all()]
        if not org_ids:
            return {
                "organizations": 0,
                "total_assets": 0,
                "new_assets": 0,
                "unknown_assets": 0,
                "exposed_assets": 0,
                "critical_exposures": 0,
                "changes_24h": 0,
                "attack_surface_growth_30d": 0,
                "inventory_by_type": {},
                "exposures_by_severity": {},
                "recent_changes": [],
                "top_risk_assets": [],
            }

        assets = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.organization_id.in_(org_ids),
            DiscoveredAsset.status != "historical",
        ).all()
        active_assets = [a for a in assets if a.status != "inactive" and a.ownership_status != "rejected"]
        open_exposures = self.db.query(Exposure).filter(
            Exposure.organization_id.in_(org_ids),
            Exposure.status.in_(["open", "in_progress"]),
        ).all()
        exposed_asset_ids = {e.discovered_asset_id for e in open_exposures if e.discovered_asset_id}
        cutoff_24h = self._now() - timedelta(hours=24)
        cutoff_30d = self._now() - timedelta(days=30)
        changes_24h = self.db.query(AssetChange).filter(
            AssetChange.organization_id.in_(org_ids),
            AssetChange.detected_at >= cutoff_24h,
        ).count()
        current_count = len(active_assets)
        created_last_30 = len([a for a in active_assets if (self._as_utc(a.first_seen) or cutoff_30d) >= cutoff_30d])
        baseline = max(0, current_count - created_last_30)
        growth = round((created_last_30 / baseline) * 100, 1) if baseline else (100.0 if created_last_30 else 0.0)

        recent = self.list_changes(organization_scope, organization_id=selected, limit=8)["changes"]
        top_assets = sorted(active_assets, key=lambda item: (item.risk_score or 0, item.last_seen), reverse=True)[:8]
        org_names = dict(
            self.db.query(Organization.id, Organization.name).filter(Organization.id.in_(org_ids)).all()
        )
        return {
            "organizations": len(org_ids),
            "total_assets": current_count,
            "new_assets": len([a for a in active_assets if a.status == "new"]),
            "unknown_assets": len([a for a in active_assets if a.ownership_status == "requires_investigation"]),
            "exposed_assets": len(exposed_asset_ids),
            "critical_exposures": len([e for e in open_exposures if self._severity(e.severity) == "critical"]),
            "changes_24h": changes_24h,
            "attack_surface_growth_30d": growth,
            "inventory_by_type": dict(Counter(a.asset_type for a in active_assets)),
            "exposures_by_severity": dict(Counter(self._severity(e.severity) for e in open_exposures)),
            "recent_changes": recent,
            "top_risk_assets": [
                self._serialize_asset(a, org_names.get(a.organization_id)) for a in top_assets
            ],
        }

    def graph(self, organization_scope: Optional[str], organization_id: str) -> dict[str, Any]:
        """Return active inventory nodes and relationship edges for visualization."""
        if organization_scope and organization_id != organization_scope:
            raise ValueError("Organization not found")
        organization = self.db.query(Organization).filter(Organization.id == organization_id, Organization.status == "active").first()
        if not organization:
            raise ValueError("Organization not found")

        nodes = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.organization_id == organization_id,
            DiscoveredAsset.status.notin_(["inactive", "historical"]),
            DiscoveredAsset.ownership_status != "rejected",
        ).order_by(DiscoveredAsset.asset_type, DiscoveredAsset.value).all()
        node_ids = {node.id for node in nodes}
        edges = []
        if node_ids:
            edges = self.db.query(AssetRelationship).filter(
                AssetRelationship.organization_id == organization_id,
                AssetRelationship.is_active.is_(True),
                AssetRelationship.source_asset_id.in_(node_ids),
                AssetRelationship.target_asset_id.in_(node_ids),
            ).order_by(AssetRelationship.relationship_type).all()
        return {
            "organization": {"id": organization.id, "name": organization.name},
            "nodes": [self._serialize_asset(node, organization.name) for node in nodes],
            "edges": [
                {
                    "id": edge.id,
                    "source": edge.source_asset_id,
                    "target": edge.target_asset_id,
                    "relationship_type": edge.relationship_type,
                    "confidence_score": edge.confidence_score,
                    "first_seen": edge.first_seen,
                    "last_seen": edge.last_seen,
                }
                for edge in edges
            ],
        }

    def list_inventory(
        self,
        user_id: str,
        *,
        organization_id: Optional[str] = None,
        asset_type: Optional[str] = None,
        status: Optional[str] = None,
        ownership_status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        query = self.db.query(DiscoveredAsset)
        if user_id:
            query = query.filter(DiscoveredAsset.organization_id == user_id)
        if organization_id:
            query = query.filter(DiscoveredAsset.organization_id == organization_id)
        if asset_type:
            query = query.filter(DiscoveredAsset.asset_type == asset_type)
        if status:
            query = query.filter(DiscoveredAsset.status == status)
        if ownership_status:
            query = query.filter(DiscoveredAsset.ownership_status == ownership_status)
        if search:
            q = f"%{search.strip()}%"
            query = query.filter(
                or_(DiscoveredAsset.value.ilike(q), DiscoveredAsset.display_name.ilike(q))
            )
        rows = query.order_by(
            DiscoveredAsset.risk_score.desc(), DiscoveredAsset.last_seen.desc()
        ).limit(limit).all()
        org_names = dict(
            self.db.query(Organization.id, Organization.name).filter(
                Organization.id.in_({r.organization_id for r in rows})
            ).all()
        ) if rows else {}
        return {
            "assets": [self._serialize_asset(row, org_names.get(row.organization_id)) for row in rows],
            "total": len(rows),
        }

    @staticmethod
    def _serialize_asset(row: DiscoveredAsset, organization_name: Optional[str] = None) -> dict[str, Any]:
        try:
            metadata = json.loads(row.metadata_json or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        return {
            "id": row.id,
            "organization_id": row.organization_id,
            "organization_name": organization_name,
            "asset_type": row.asset_type,
            "value": row.value,
            "display_name": row.display_name,
            "status": row.status,
            "ownership_status": row.ownership_status,
            "confidence_score": row.confidence_score,
            "criticality": row.criticality,
            "internet_exposed": row.internet_exposed,
            "risk_score": row.risk_score,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "metadata": metadata,
        }

    def asset_detail(self, user_id: str, discovered_asset_id: str) -> dict[str, Any]:
        row = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.id == discovered_asset_id,
            *([DiscoveredAsset.organization_id == user_id] if user_id else []),
        ).first()
        if not row:
            raise ValueError("Attack-surface asset not found")
        organization = self.db.query(Organization).filter(Organization.id == row.organization_id).first()
        relationships = self.db.query(AssetRelationship).filter(
            AssetRelationship.organization_id == row.organization_id,
            or_(
                AssetRelationship.source_asset_id == row.id,
                AssetRelationship.target_asset_id == row.id,
            ),
        ).order_by(AssetRelationship.last_seen.desc()).all()
        peer_ids = {
            relation.target_asset_id if relation.source_asset_id == row.id else relation.source_asset_id
            for relation in relationships
        }
        peers = {
            peer.id: peer
            for peer in self.db.query(DiscoveredAsset).filter(DiscoveredAsset.id.in_(peer_ids)).all()
        } if peer_ids else {}
        changes = self.list_changes(user_id, organization_id=row.organization_id, discovered_asset_id=row.id, limit=50)["changes"]
        exposures = self.list_exposures(user_id, organization_id=row.organization_id, discovered_asset_id=row.id, limit=50)["exposures"]
        observations = self.db.query(AssetObservation).filter(
            AssetObservation.discovered_asset_id == row.id
        ).order_by(AssetObservation.observed_at.desc()).limit(30).all()
        return {
            "asset": self._serialize_asset(row, organization.name if organization else None),
            "relationships": [
                {
                    "id": relation.id,
                    "direction": "outbound" if relation.source_asset_id == row.id else "inbound",
                    "relationship_type": relation.relationship_type,
                    "is_active": relation.is_active,
                    "confidence_score": relation.confidence_score,
                    "first_seen": relation.first_seen,
                    "last_seen": relation.last_seen,
                    "peer": self._serialize_asset(peers[peer_id], organization.name if organization else None) if (peer_id := (relation.target_asset_id if relation.source_asset_id == row.id else relation.source_asset_id)) in peers else None,
                }
                for relation in relationships
            ],
            "changes": changes,
            "exposures": exposures,
            "observations": [
                {
                    "id": obs.id,
                    "scan_id": obs.scan_id,
                    "observed_at": obs.observed_at,
                    "state_hash": obs.state_hash,
                }
                for obs in observations
            ],
        }

    def list_changes(
        self,
        user_id: str,
        *,
        organization_id: Optional[str] = None,
        discovered_asset_id: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        query = self.db.query(AssetChange, DiscoveredAsset, Organization).join(
            Organization, AssetChange.organization_id == Organization.id
        ).outerjoin(DiscoveredAsset, AssetChange.discovered_asset_id == DiscoveredAsset.id)
        if user_id:
            query = query.filter(AssetChange.organization_id == user_id)
        if organization_id:
            query = query.filter(AssetChange.organization_id == organization_id)
        if discovered_asset_id:
            query = query.filter(AssetChange.discovered_asset_id == discovered_asset_id)
        rows = query.order_by(AssetChange.detected_at.desc()).limit(limit).all()
        return {
            "changes": [
                {
                    "id": change.id,
                    "organization_id": change.organization_id,
                    "organization_name": organization.name,
                    "asset_id": discovered.id if discovered else None,
                    "asset_value": discovered.display_name or discovered.value if discovered else None,
                    "asset_type": discovered.asset_type if discovered else None,
                    "change_type": change.change_type,
                    "severity": change.severity,
                    "title": change.title,
                    "detected_at": change.detected_at,
                    "is_acknowledged": change.is_acknowledged,
                }
                for change, discovered, organization in rows
            ],
            "total": len(rows),
        }

    def list_exposures(
        self,
        user_id: str,
        *,
        organization_id: Optional[str] = None,
        discovered_asset_id: Optional[str] = None,
        status: Optional[str] = "open",
        severity: Optional[str] = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        query = self.db.query(Exposure, DiscoveredAsset, Organization).join(
            Organization, Exposure.organization_id == Organization.id
        ).outerjoin(DiscoveredAsset, Exposure.discovered_asset_id == DiscoveredAsset.id)
        if user_id:
            query = query.filter(Exposure.organization_id == user_id)
        if organization_id:
            query = query.filter(Exposure.organization_id == organization_id)
        if discovered_asset_id:
            query = query.filter(Exposure.discovered_asset_id == discovered_asset_id)
        if status:
            query = query.filter(Exposure.status == status)
        if severity:
            query = query.filter(func.lower(Exposure.severity) == severity.lower())
        rows = query.order_by(Exposure.risk_score.desc(), Exposure.last_seen.desc()).limit(limit).all()
        return {
            "exposures": [
                {
                    "id": exposure.id,
                    "organization_id": exposure.organization_id,
                    "organization_name": organization.name,
                    "asset_id": discovered.id if discovered else None,
                    "asset_value": (discovered.display_name or discovered.value) if discovered else None,
                    "asset_type": discovered.asset_type if discovered else None,
                    "exposure_type": exposure.exposure_type,
                    "title": exposure.title,
                    "severity": self._severity(exposure.severity),
                    "risk_score": exposure.risk_score,
                    "cvss_score": exposure.cvss_score,
                    "cve_id": exposure.cve_id,
                    "internet_exposed": exposure.internet_exposed,
                    "exploitability": exposure.exploitability,
                    "status": exposure.status,
                    "first_seen": exposure.first_seen,
                    "last_seen": exposure.last_seen,
                    "resolved_at": exposure.resolved_at,
                }
                for exposure, discovered, organization in rows
            ],
            "total": len(rows),
        }

    def update_exposure_status(
        self,
        user_id: str,
        exposure_id: str,
        status: str,
    ) -> Exposure:
        allowed = {"open", "in_progress", "accepted_risk", "false_positive", "resolved"}
        if status not in allowed:
            raise ValueError("Invalid exposure status")
        exposure = self.db.query(Exposure).filter(
            Exposure.id == exposure_id,
            *([Exposure.organization_id == user_id] if user_id else []),
        ).first()
        if not exposure:
            raise ValueError("Exposure not found")
        previous = exposure.status
        exposure.status = status
        exposure.resolved_at = self._now() if status == "resolved" else None
        if previous != status:
            asset = None
            if exposure.discovered_asset_id:
                asset = self.db.query(DiscoveredAsset).filter(
                    DiscoveredAsset.id == exposure.discovered_asset_id
                ).first()
            self._record_change(
                exposure.organization_id,
                asset,
                exposure.scan_id,
                "remediation_status_changed",
                f"Exposure status changed to {status.replace('_', ' ')}: {exposure.title}",
                severity="info",
                details={"previous_status": previous, "status": status, "exposure_id": exposure.id},
            )
        if exposure.discovered_asset_id:
            asset = self.db.query(DiscoveredAsset).filter(
                DiscoveredAsset.id == exposure.discovered_asset_id
            ).first()
            if asset:
                max_risk = self.db.query(func.max(Exposure.risk_score)).filter(
                    Exposure.discovered_asset_id == asset.id,
                    Exposure.status.in_(["open", "in_progress"]),
                ).scalar()
                asset.risk_score = int(max_risk or 0)
        self.db.commit()
        self.db.refresh(exposure)
        return exposure

    def update_asset_context(
        self,
        user_id: str,
        discovered_asset_id: str,
        *,
        criticality: Optional[str] = None,
        ownership_status: Optional[str] = None,
    ) -> DiscoveredAsset:
        row = self.db.query(DiscoveredAsset).filter(
            DiscoveredAsset.id == discovered_asset_id,
            *([DiscoveredAsset.organization_id == user_id] if user_id else []),
        ).first()
        if not row:
            raise ValueError("Attack-surface asset not found")
        if criticality is not None:
            if criticality not in {"critical", "high", "normal", "low"}:
                raise ValueError("Invalid criticality")
            row.criticality = criticality
        if ownership_status is not None:
            if ownership_status not in {"confirmed", "high_confidence", "requires_investigation", "rejected"}:
                raise ValueError("Invalid ownership status")
            previous_ownership = row.ownership_status
            row.ownership_status = ownership_status
            row.confidence_score = 1.0 if ownership_status == "confirmed" else row.confidence_score

            # Human confirmation is the gate that turns an inferred external
            # certificate/SAN candidate into an approved discovery seed. The
            # scanner never expands scope to candidate domains automatically.
            if row.asset_type == "candidate_domain" and ownership_status == "confirmed":
                seed = self.db.query(DiscoverySeed).filter(
                    DiscoverySeed.organization_id == row.organization_id,
                    DiscoverySeed.seed_type == "domain",
                    DiscoverySeed.value == row.value,
                ).first()
                if not seed:
                    self.db.add(DiscoverySeed(
                        organization_id=row.organization_id,
                        seed_type="domain",
                        value=row.value,
                        is_primary=False,
                        is_active=True,
                        ownership_status="confirmed",
                        confidence_score=1.0,
                    ))
                else:
                    seed.is_active = True
                    seed.ownership_status = "confirmed"
                    seed.confidence_score = 1.0

                root_asset = self.db.query(Asset).filter(Asset.organization_id == row.organization_id, Asset.status != "archived").first()
                domain = self.db.query(Domain).filter(
                    Domain.organization_id == row.organization_id,
                    Domain.domain == row.value,
                ).first()
                if not domain and root_asset:
                    self.db.add(Domain(
                        organization_id=row.organization_id,
                        asset_id=root_asset.id,
                        domain=row.value,
                        is_active=True,
                        is_vulnerable=False,
                        scan_status="not_scanned",
                    ))

                existing_domain_asset = self.db.query(DiscoveredAsset).filter(
                    DiscoveredAsset.organization_id == row.organization_id,
                    DiscoveredAsset.asset_type == "domain",
                    DiscoveredAsset.value == row.value,
                    DiscoveredAsset.id != row.id,
                ).first()
                if existing_domain_asset:
                    row.status = "historical"
                    row.internet_exposed = False
                else:
                    row.asset_type = "domain"
                    row.status = "changed"
                self._record_change(
                    row.organization_id,
                    row,
                    row.last_seen_scan_id,
                    "candidate_confirmed",
                    f"Candidate approved for monitoring: {row.value}",
                    severity="low",
                    details={"previous_ownership": previous_ownership, "discovery_seed_created": True},
                )
        open_exposures = self.db.query(Exposure).filter(
            Exposure.discovered_asset_id == row.id,
            Exposure.status.in_(["open", "in_progress"]),
        ).all()
        for exposure in open_exposures:
            exposure.risk_score = self._risk_score(
                exposure.severity,
                row.criticality,
                exposure.internet_exposed,
            )
        row.risk_score = max([e.risk_score for e in open_exposures], default=0)
        self.db.commit()
        self.db.refresh(row)
        return row
