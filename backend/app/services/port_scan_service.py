"""
Phase 2-3: Port Scanning, Service Detection, Vulnerability Engine.
"""

from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Subdomain, Domain
from app.models.phase2 import Port, Service, Banner, Technology, OSDetection, Vulnerability
from app.exceptions import NotFoundError, ValidationError
import logging

logger = logging.getLogger(__name__)


class PortScanService:
    """Service for port scanning and service detection."""

    def __init__(self, db: Session):
        self.db = db

    def create_port(
        self,
        subdomain_id: str,
        port_number: int,
        protocol: str = "TCP",
        service_name: Optional[str] = None,
        status: str = "open"
    ) -> Port:
        """Create port record."""
        if not (0 < port_number < 65536):
            raise ValidationError(f"Invalid port number: {port_number}")

        try:
            port = self.db.add(Port(
                subdomain_id=subdomain_id,
                port_number=port_number,
                protocol=protocol.upper(),
                service_name=service_name,
                status=status
            ))
            self.db.commit()
            self.db.refresh(port)
            logger.debug(f"Port {port_number} created for subdomain {subdomain_id}")
            return port
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating port: {str(e)}")
            raise

    def create_service(
        self,
        port_id: str,
        service_name: str,
        version: Optional[str] = None,
        product: Optional[str] = None,
        os_type: Optional[str] = None,
        confidence: float = 0.0
    ) -> Service:
        """Create service detection record."""
        try:
            service = self.db.add(Service(
                port_id=port_id,
                service_name=service_name,
                version=version,
                product=product,
                os_type=os_type,
                confidence=confidence
            ))
            self.db.commit()
            self.db.refresh(service)
            logger.debug(f"Service {service_name} created for port {port_id}")
            return service
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating service: {str(e)}")
            raise

    def add_banner(
        self,
        service_id: str,
        raw_banner: str,
        parsed_version: Optional[str] = None,
        cpe: Optional[str] = None
    ) -> Banner:
        """Record banner/version information."""
        try:
            banner = self.db.add(Banner(
                service_id=service_id,
                raw_banner=raw_banner,
                parsed_version=parsed_version,
                cpe=cpe
            ))
            self.db.commit()
            self.db.refresh(banner)
            return banner
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error adding banner: {str(e)}")
            raise

    def detect_technology(
        self,
        subdomain_id: str,
        technology_name: str,
        tech_type: Optional[str] = None,
        version: Optional[str] = None,
        confidence: float = 0.0
    ) -> Technology:
        """Record detected technology."""
        try:
            tech = self.db.add(Technology(
                subdomain_id=subdomain_id,
                technology_name=technology_name,
                technology_type=tech_type,
                version=version,
                confidence=confidence
            ))
            self.db.commit()
            self.db.refresh(tech)
            logger.debug(f"Technology {technology_name} detected on {subdomain_id}")
            return tech
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error detecting technology: {str(e)}")
            raise

    def detect_os(
        self,
        subdomain_id: str,
        os_name: Optional[str] = None,
        os_version: Optional[str] = None,
        confidence: float = 0.0,
        method: str = "ttl_analysis"
    ) -> OSDetection:
        """Record OS detection."""
        try:
            os_det = self.db.add(OSDetection(
                subdomain_id=subdomain_id,
                os_name=os_name,
                os_version=os_version,
                confidence=confidence,
                detection_method=method
            ))
            self.db.commit()
            self.db.refresh(os_det)
            logger.debug(f"OS detected on {subdomain_id}: {os_name}")
            return os_det
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error detecting OS: {str(e)}")
            raise

    def get_subdomain_ports(self, subdomain_id: str) -> List[Port]:
        """Get all ports for subdomain."""
        try:
            return self.db.query(Port).filter(
                Port.subdomain_id == subdomain_id
            ).order_by(Port.port_number).all()
        except Exception as e:
            logger.error(f"Error fetching ports: {str(e)}")
            return []

    def get_port_details(self, port_id: str) -> Dict[str, Any]:
        """Get detailed port information with services."""
        try:
            port = self.db.query(Port).filter(Port.id == port_id).first()
            if not port:
                raise NotFoundError("Port")

            services = self.db.query(Service).filter(
                Service.port_id == port_id
            ).all()

            return {
                "port": port,
                "services": services,
                "service_count": len(services)
            }
        except Exception as e:
            logger.error(f"Error getting port details: {str(e)}")
            raise

    def get_subdomain_summary(self, subdomain_id: str) -> Dict[str, Any]:
        """Get security summary for subdomain."""
        try:
            ports = self.db.query(Port).filter(
                Port.subdomain_id == subdomain_id
            ).all()

            technologies = self.db.query(Technology).filter(
                Technology.subdomain_id == subdomain_id
            ).all()

            os_detect = self.db.query(OSDetection).filter(
                OSDetection.subdomain_id == subdomain_id
            ).first()

            open_ports = [p for p in ports if p.status == "open"]
            services_count = sum(len(p.services) for p in ports)

            return {
                "subdomain_id": subdomain_id,
                "total_ports": len(ports),
                "open_ports": len(open_ports),
                "services_detected": services_count,
                "technologies": len(technologies),
                "os_detected": os_detect.os_name if os_detect else None,
                "security_score": self._calculate_security_score(
                    len(open_ports), services_count, len(technologies)
                )
            }
        except Exception as e:
            logger.error(f"Error getting subdomain summary: {str(e)}")
            raise

    def _calculate_security_score(self, ports: int, services: int, techs: int) -> int:
        """Calculate security score based on exposure."""
        score = min(100, (ports * 10) + (services * 5) + (techs * 2))
        return score


class VulnerabilityService:
    """Phase 3: Vulnerability matching and CVE database."""

    def __init__(self, db: Session):
        self.db = db

    def add_vulnerability(
        self,
        service_id: Optional[str],
        cve_id: str,
        title: str,
        description: Optional[str] = None,
        severity: str = "Medium",
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        published_date: Optional[str] = None
    ) -> Vulnerability:
        """Add vulnerability to database."""
        try:
            vuln = self.db.add(Vulnerability(
                service_id=service_id,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published_date
            ))
            self.db.commit()
            self.db.refresh(vuln)
            logger.info(f"Vulnerability {cve_id} added")
            return vuln
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error adding vulnerability: {str(e)}")
            raise

    def get_service_vulnerabilities(self, service_id: str) -> List[Vulnerability]:
        """Get vulnerabilities for a service."""
        try:
            return self.db.query(Vulnerability).filter(
                Vulnerability.service_id == service_id
            ).order_by(Vulnerability.cvss_score.desc()).all()
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {str(e)}")
            return []

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Vulnerability]:
        """Get vulnerabilities by severity level."""
        try:
            return self.db.query(Vulnerability).filter(
                Vulnerability.severity == severity
            ).all()
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {str(e)}")
            return []

    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        """Get all critical vulnerabilities."""
        return self.get_vulnerabilities_by_severity("Critical")
