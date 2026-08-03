"""Domain discovery and real ProjectDiscovery scanner orchestration."""

from __future__ import annotations

import json
import logging
from threading import Lock
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.exceptions import NotFoundError, ValidationError
from app.models import DNSRecord, Domain, Scan, Subdomain
from app.repositories.domain_repo import DomainRepository
from app.repositories.scan_repo import ScanRepository


logger = logging.getLogger(__name__)

_live_scan_lock = Lock()
_live_scan_states: dict[str, dict[str, Any]] = {}


def get_live_scan_state(scan_id: str) -> dict[str, Any]:
    """Return a copy of transient progress for a scan running in this process."""
    with _live_scan_lock:
        state = _live_scan_states.get(scan_id, {})
        return {
            **state,
            "live_subdomains": sorted(state.get("live_subdomains", set())),
        }
def _set_live_scan_state(scan_id: str, **changes: Any) -> None:
    with _live_scan_lock:
        state = _live_scan_states.setdefault(scan_id, {"live_subdomains": set()})
        state.update(changes)
def clear_live_scan_state(scan_id: str) -> None:
    """Remove transient in-memory progress for a scan."""
    with _live_scan_lock:
        _live_scan_states.pop(scan_id, None)
def _add_live_subdomain(scan_id: str, hostname: str) -> int:
    with _live_scan_lock:
        state = _live_scan_states.setdefault(scan_id, {"live_subdomains": set()})
        values = state.setdefault("live_subdomains", set())
        values.add(hostname)
        return len(values)
class DiscoveryService:
    """Service for reconnaissance and discovery operations."""

    def __init__(self, db: Session):
        self.db = db
        self.domain_repo = DomainRepository(db)
        self.scan_repo = ScanRepository(db)

    def create_domain(self, asset_id: str, domain: str) -> Domain:
        """Create a normalized domain for an asset."""
        normalized = (domain or "").strip().lower().rstrip(".")
        if not self._is_valid_domain(normalized):
            raise ValidationError(f"Invalid domain format: {domain}")

        existing = self.domain_repo.get_by_domain_name(asset_id, normalized)
        if existing:
            return existing

        return self.domain_repo.create({
            "asset_id": asset_id,
            "domain": normalized,
            "is_active": True,
            "is_vulnerable": False,
            "scan_status": "not_scanned",
        })

    def create_subdomain(
        self,
        domain_id: str,
        subdomain: str,
        ip_addresses: Optional[List[str]] = None,
        is_responsive: bool = False,
        status_code: Optional[int] = None,
    ) -> Subdomain:
        """Create a discovered subdomain if it does not already exist."""
        normalized = (subdomain or "").strip().lower().rstrip(".")
        if not self._is_valid_subdomain(normalized):
            raise ValidationError(f"Invalid subdomain format: {subdomain}")
        if not self.domain_repo.get_by_id(domain_id):
            raise NotFoundError("Domain")

        existing = self.db.query(Subdomain).filter(
            Subdomain.domain_id == domain_id,
            Subdomain.subdomain == normalized,
        ).first()
        if existing:
            return existing

        try:
            value = Subdomain(
                domain_id=domain_id,
                subdomain=normalized,
                ip_addresses=json.dumps(ip_addresses or []),
                is_responsive=is_responsive,
                response_status_code=status_code,
            )
            self.db.add(value)
            self.db.commit()
            self.db.refresh(value)
            return value
        except Exception:
            self.db.rollback()
            raise

    def create_dns_record(
        self,
        domain_id: str,
        record_type: str,
        record_value: str,
        ttl: Optional[int] = None,
    ) -> DNSRecord:
        """Create a real DNS record."""
        valid_types = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"}
        if record_type not in valid_types:
            raise ValidationError(f"Invalid DNS record type: {record_type}")

        try:
            value = DNSRecord(
                domain_id=domain_id,
                record_type=record_type,
                record_value=record_value,
                ttl=ttl,
            )
            self.db.add(value)
            self.db.commit()
            self.db.refresh(value)
            return value
        except Exception:
            self.db.rollback()
            raise

    def get_domain_discoveries(self, domain_id: str) -> Dict[str, Any]:
        """Return persisted discoveries for a domain."""
        domain = self.domain_repo.get_by_id(domain_id)
        if not domain:
            raise NotFoundError("Domain")
        subdomains = self.db.query(Subdomain).filter(Subdomain.domain_id == domain_id).all()
        dns_records = self.db.query(DNSRecord).filter(DNSRecord.domain_id == domain_id).all()
        return {
            "domain": domain.domain,
            "subdomains": [{
                "id": value.id,
                "subdomain": value.subdomain,
                "is_responsive": value.is_responsive,
                "status_code": value.response_status_code,
                "has_ssl": value.has_ssl,
                "ip_addresses": self._json_list(value.ip_addresses),
            } for value in subdomains],
            "dns_records": [{
                "id": value.id,
                "type": value.record_type,
                "value": value.record_value,
                "ttl": value.ttl,
            } for value in dns_records],
            "total_subdomains": len(subdomains),
            "total_dns_records": len(dns_records),
        }

    def initiate_scan(
        self,
        asset_id: str,
        domain_id: str,
        scan_type: str = "discovery",
    ) -> Scan:
        """Create a queued scan for a real target."""
        valid_types = {
            "discovery", "ssl", "screenshot", "dns", "port_scan",
            "tech_detect", "full", "recon_full", "scheduled_full", "quick",
            "vuln_scan", "ssl_check",
        }
        if scan_type not in valid_types:
            raise ValidationError(f"Invalid scan type: {scan_type}")

        domain = self.domain_repo.get_by_id(domain_id)
        if not domain or domain.asset_id != asset_id:
            raise NotFoundError("Domain")

        scan = self.scan_repo.create({
            "asset_id": asset_id,
            "scan_type": scan_type,
            "status": "pending",
            "target_domain": domain.domain,
            "discovered_count": 0,
            "vulnerable_count": 0,
        })
        self.domain_repo.update_scan_status(domain_id, "scanning")
        return scan

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        import re

        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return re.match(pattern, domain or "") is not None

    @staticmethod
    def _is_valid_subdomain(subdomain: str) -> bool:
        import re

        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        return re.match(pattern, subdomain or "") is not None

    @staticmethod
    def _json_list(value) -> list:
        if not value:
            return []
        if isinstance(value, list):
            return value
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []

    def run_scan_simulation(self, scan_id: str, domain_id: str):
        """Legacy method name retained; it now runs only the real scanner."""
        from app.utils.database import SessionLocal

        job_db = SessionLocal()
        try:
            DiscoveryService(job_db).run_real_scan(scan_id, domain_id)
        finally:
            job_db.close()

    def run_real_scan(self, scan_id: str, domain_id: str):
        """Execute the real toolchain and report a real failure on errors."""
        from datetime import datetime, timezone

        from sqlalchemy import text

        from app.models import Asset

        domain = None
        try:
            _set_live_scan_state(
                scan_id,
                status="starting",
                current_tool=None,
                progress=0,
                domain_id=domain_id,
                live_subdomains=set(),
            )
            try:
                self.db.execute(text("SET app.bypass_rls = 'true'"))
            except Exception:
                self.db.rollback()

            scan = self.scan_repo.get_by_id(scan_id)
            domain = self.domain_repo.get_by_id(domain_id)
            if not scan or not domain or domain.asset_id != scan.asset_id:
                raise NotFoundError("Scan target")

            self.scan_repo.update_status(scan_id, "running")
            _set_live_scan_state(
                scan_id,
                status="running",
                current_tool=None,
                progress=0,
            )
            self.domain_repo.update_scan_status(domain_id, "scanning")
            result = self._run_projectdiscovery_pipeline(scan, domain)

            warnings = result.get("warnings", [])
            warning_message = "\n".join(warnings) if warnings else None
            self.scan_repo.update(scan_id, {
                "discovered_count": result["discovered_count"],
                "vulnerable_count": result["vulnerable_count"],
                "error_message": warning_message,
            })
            self.scan_repo.update_status(scan_id, "completed")
            _set_live_scan_state(
                scan_id,
                status="completed",
                current_tool=None,
                progress=100,
            )

            domain.scan_status = "completed"
            domain.is_vulnerable = result["vulnerable_count"] > 0
            domain.last_scanned = datetime.now(timezone.utc)

            asset = self.db.query(Asset).filter(Asset.id == scan.asset_id).first()
            if asset:
                asset.scan_count = (asset.scan_count or 0) + 1
                asset.last_scanned_at = datetime.now(timezone.utc)
                asset.risk_score = result["risk_score"]
            self.db.commit()
            logger.info(
                "Real recon scan %s completed with %s discoveries, %s vulnerabilities, and %s warning(s)",
                scan_id,
                result["discovered_count"],
                result["vulnerable_count"],
                len(warnings),
            )
        except Exception as exc:
            self.db.rollback()
            message = str(exc)[:4000] or exc.__class__.__name__
            _set_live_scan_state(
                scan_id,
                status="failed",
                current_tool=None,
                error=message,
            )
            logger.exception("Real recon scan %s failed: %s", scan_id, message)
            try:
                self.scan_repo.update_status(scan_id, "failed")
                self.scan_repo.set_error(scan_id, message)
                if domain:
                    domain.scan_status = "failed"
                    self.db.commit()
            except Exception:
                self.db.rollback()

    def _run_projectdiscovery_pipeline(self, scan: Scan, domain: Domain) -> Dict[str, Any]:
        """Run the real multi-tool scanner pipeline and persist factual output."""
        import subprocess
        import tempfile
        from datetime import datetime, timezone
        from pathlib import Path
        from urllib.parse import urlparse
        from xml.etree import ElementTree

        from app.models import DNSRecord, Screenshot, Secret, Subdomain
        from app.models.phase2 import Port, Service, Vulnerability
        from app.services.extended_recon_service import (
            collect_additional_subdomains,
            collect_additional_urls,
            run_specialized_assessments,
        )
        from app.services.recon_tool_service import (
            enabled_recon_tool_paths,
            inspect_chromium,
            inspect_recon_tools,
            unavailable_tool_messages,
        )

        tools = enabled_recon_tool_paths(settings)
        tool_statuses = inspect_recon_tools(
            probe=settings.recon_tool_probe_on_scan_start,
            config=settings,
        )
        unavailable = unavailable_tool_messages(tool_statuses)
        if unavailable:
            raise RuntimeError(f"Unavailable scanner tools: {', '.join(unavailable)}")

        chromium_status = inspect_chromium(
            probe=settings.recon_tool_probe_on_scan_start,
            config=settings,
        )
        if not chromium_status["available"]:
            reason = chromium_status.get("error") or "unavailable"
            raise RuntimeError(
                f"Chromium cannot capture real screenshots: {reason}"
            )
        chromium = Path(chromium_status["path"])

        # Progress is derived from the position of the active pipeline stage,
        # not from hardcoded percentages. Tool names remain internal and are
        # never exposed through the live scan status returned to the frontend.
        pipeline_stages = [
            "asset_discovery",
            "dns_resolution",
            "port_discovery",
            "service_detection",
            "web_analysis",
            "vulnerability_analysis",
            "visual_capture",
        ]

        additional_asset_stage_enabled = bool(
            settings.sublist3r_enabled or settings.uncover_enabled
        )
        application_discovery_stage_enabled = bool(
            settings.waybackurls_enabled
            or settings.paramspider_enabled
            or settings.katana_enabled
            or settings.dirsearch_enabled
            or settings.dirb_enabled
            or settings.dirbuster_enabled
            or settings.wappalyzer_enabled
            or settings.lazyrecon_enabled
        )
        specialized_stage_enabled = bool(
            settings.wpscan_enabled
            or settings.droopescan_enabled
            or settings.secretfinder_enabled
            or settings.xsstrike_enabled
            or settings.xssvibes_enabled
            or settings.nikto_enabled
)

        if additional_asset_stage_enabled:
            pipeline_stages.insert(1, "additional_asset_discovery")
        if application_discovery_stage_enabled:
            pipeline_stages.insert(
                pipeline_stages.index("vulnerability_analysis"),
                "application_discovery",
            )
        if specialized_stage_enabled:
            pipeline_stages.insert(
                pipeline_stages.index("vulnerability_analysis"),
                "specialized_assessment",
            )
        gemini_stage_enabled = bool(
            settings.gemini_service_analysis_enabled
            and settings.gemini_api_key
            and str(settings.gemini_api_key).strip().lower() != "dummy_key"
        )
        if gemini_stage_enabled:
            pipeline_stages.append("ai_service_analysis")

        stage_positions = {
            stage: position
            for position, stage in enumerate(pipeline_stages, start=1)
        }
        def set_pipeline_stage(stage: str) -> None:
            """Expose only a real stage-based percentage, never a tool name."""
            if stage not in stage_positions:
                return
            progress = min(
                99,
                max(1, round(stage_positions[stage] * 100 / len(pipeline_stages))),
            )
            _set_live_scan_state(
                scan.id,
                status="running",
                current_tool=None,
                progress=progress,
            )

        def complete_pipeline_stage(stage: str) -> None:
            """Keep progress aligned with the number of pipeline stages passed."""
            if stage not in stage_positions:
                return
            progress = min(
                99,
                max(1, round(stage_positions[stage] * 100 / len(pipeline_stages))),
            )
            _set_live_scan_state(
                scan.id,
                status="running",
                current_tool=None,
                progress=progress,
            )

        pipeline_warnings: list[str] = []

        def run_command(
            command: list[str],
            label: str,
            timeout: Optional[int],
            *,
            stage: Optional[str] = None,
            continue_on_error: bool = False,
        ) -> subprocess.CompletedProcess:
            if stage:
                set_pipeline_stage(stage)
            logger.info("Running %s for %s", label, domain.domain)
            effective_timeout = timeout if timeout and timeout > 0 else None
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=effective_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                message = (
                    f"{label} timed out after {timeout} seconds"
                    if effective_timeout is not None
                    else f"{label} timed out"
                )
                if not continue_on_error:
                    raise RuntimeError(message) from exc
                logger.warning("%s; continuing the remaining pipeline", message)
                pipeline_warnings.append(message)
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode(errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode(errors="replace")
                return subprocess.CompletedProcess(command, 124, stdout, stderr)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "unknown error").strip()
                message = f"{label} failed: {detail[-1500:]}"
                if not continue_on_error:
                    raise RuntimeError(message)
                logger.warning("%s; continuing the remaining pipeline", message)
                pipeline_warnings.append(message)
            return result

        def parse_json_lines(output: str) -> list[dict]:
            rows = []
            for line in (output or "").splitlines():
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
                except json.JSONDecodeError:
                    continue
            return rows

        def hostname_from(value: str) -> str:
            raw = (value or "").strip().lower()
            if not raw:
                return ""
            parsed = urlparse(raw if "://" in raw else f"//{raw}")
            return (parsed.hostname or raw.split("/")[0].split(":")[0]).rstrip(".")

        target = domain.domain.strip().lower()
        screenshot_dir = Path("/app/screenshots") / scan.id
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        def persist_live_subdomain(raw_hostname: str) -> str:
            """Persist a factual subfinder result immediately for live polling."""
            hostname = hostname_from(raw_hostname)
            if not hostname or (hostname != target and not hostname.endswith(f".{target}")):
                return ""

            count = _add_live_subdomain(scan.id, hostname)
            existing = self.db.query(Subdomain).filter(
                Subdomain.domain_id == domain.id,
                Subdomain.subdomain == hostname,
            ).first()
            if not existing:
                self.db.add(Subdomain(
                    domain_id=domain.id,
                    subdomain=hostname,
                    ip_addresses="[]",
                    is_responsive=False,
                    technologies="[]",
                ))

            scan.discovered_count = count
            self.db.commit()
            return hostname

        def run_subfinder_live(command: list[str], timeout: int) -> subprocess.CompletedProcess:
            """Stream subfinder stdout so each discovery is visible before it exits."""
            from queue import Empty, Queue
            from threading import Thread
            from time import monotonic

            label = "subfinder"
            set_pipeline_stage("asset_discovery")
            logger.info("Running %s for %s", label, domain.domain)

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            output_queue: Queue[Optional[str]] = Queue()
            error_lines: list[str] = []

            def read_output() -> None:
                assert process.stdout is not None
                for line in process.stdout:
                    output_queue.put(line)
                output_queue.put(None)

            def read_errors() -> None:
                assert process.stderr is not None
                error_lines.extend(
                    line.strip()
                    for line in process.stderr
                    if line.strip()
                )

            reader = Thread(target=read_output, daemon=True)
            error_reader = Thread(target=read_errors, daemon=True)
            reader.start()
            error_reader.start()
            output_lines: list[str] = []
            deadline = monotonic() + timeout

            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    raise RuntimeError(f"{label} timed out after {timeout} seconds")
                try:
                    line = output_queue.get(timeout=min(0.25, remaining))
                except Empty:
                    if process.poll() is not None and not reader.is_alive():
                        break
                    continue
                if line is None:
                    break
                clean_line = line.strip()
                if not clean_line:
                    continue
                output_lines.append(clean_line)
                persisted = persist_live_subdomain(clean_line)
                if persisted:
                    logger.info(
                        "Live subdomain discovered for scan %s: %s",
                        scan.id,
                        persisted,
                    )

            reader.join(timeout=1)
            error_reader.join(timeout=1)
            return_code = process.wait()
            output = "\n".join(output_lines)
            error_output = "\n".join(error_lines)
            if return_code != 0:
                detail = error_output or output or "unknown error"
                raise RuntimeError(f"{label} failed: {detail[-1500:]}")
            return subprocess.CompletedProcess(command, return_code, output, error_output)

        with tempfile.TemporaryDirectory(prefix=f"asm-recon-{scan.id[:8]}-") as temp_dir:
            temp_path = Path(temp_dir)
            hosts_file = temp_path / "hosts.txt"
            urls_file = temp_path / "urls.txt"
            gowitness_jsonl = temp_path / "gowitness.jsonl"

            subfinder_result = run_subfinder_live(
                [
                    str(tools["subfinder"]),
                    "-d", target,
                    "-silent",
                    "-timeout", "10",
                    "-max-time", "2",
                ],
                150,
            )
            complete_pipeline_stage("asset_discovery")
            hostnames = {
                hostname_from(line)
                for line in subfinder_result.stdout.splitlines()
                if hostname_from(line)
            }
            hostnames.add(target)

            if additional_asset_stage_enabled:
                set_pipeline_stage("additional_asset_discovery")
                additional_hosts = collect_additional_subdomains(
                    target=target,
                    temp_path=temp_path,
                    tools=tools,
                    run_command=run_command,
                )
                for additional_host in sorted(additional_hosts):
                    hostnames.add(additional_host)
                    persist_live_subdomain(additional_host)
                complete_pipeline_stage("additional_asset_discovery")

            hosts_file.write_text("\n".join(sorted(hostnames)) + "\n", encoding="utf-8")

            dnsx_result = run_command(
                [
                    str(tools["dnsx"]),
                    "-l", str(hosts_file),
                    "-a", "-aaaa", "-cname",
                    "-json", "-silent",
                    "-timeout", "5",
                    "-retry", "1",
                ],
                "dnsx",
                180,
                stage="dns_resolution",
            )
            complete_pipeline_stage("dns_resolution")
            dns_rows = parse_json_lines(dnsx_result.stdout)

            naabu_result = run_command(
                [
                    str(tools["naabu"]),
                    "-l", str(hosts_file),
                    "-top-ports", "100",
                    "-json", "-silent",
                    "-scan-type", "c",
                    "-Pn",
                    "-timeout", "3000",
                    "-retries", "1",
                    "-rate", "1000",
                ],
                "naabu",
                420,
                stage="port_discovery",
            )
            complete_pipeline_stage("port_discovery")
            port_rows = parse_json_lines(naabu_result.stdout)

            # Naabu identifies open ports quickly; Nmap then fingerprints only
            # those exact ports instead of launching another broad port scan.
            nmap_targets: dict[str, dict[str, Any]] = {}
            for row in port_rows:
                host = hostname_from(str(row.get("input") or row.get("host") or ""))
                try:
                    port_number = int(row.get("port"))
                except (TypeError, ValueError):
                    continue
                if not host or not (1 <= port_number <= 65535):
                    continue
                entry = nmap_targets.setdefault(host, {
                    "address": str(row.get("ip") or row.get("host") or host),
                    "ports": set(),
                })
                entry["ports"].add(port_number)

            nmap_rows: list[dict[str, Any]] = []
            set_pipeline_stage("service_detection")
            for host, nmap_target in sorted(nmap_targets.items()):
                ports = sorted(nmap_target["ports"])
                if not ports:
                    continue
                logger.info(
                    "Nmap service detection for %s on ports %s",
                    host,
                    ",".join(str(port) for port in ports),
                )
                nmap_result = run_command(
                    [
                        str(tools["nmap"]),
                        "-sV",
                        "--version-light",
                        "-Pn",
                        "-n",
                        "-T4",
                        "--max-retries", "1",
                        "--host-timeout", "120s",
                        "-p", ",".join(str(port) for port in ports),
                        "-oX", "-",
                        nmap_target["address"],
                    ],
                    "nmap",
                    150,
                )
                try:
                    nmap_root = ElementTree.fromstring(nmap_result.stdout)
                except ElementTree.ParseError as exc:
                    raise RuntimeError(f"nmap returned invalid XML for {host}") from exc

                for port_node in nmap_root.findall(".//port"):
                    state_node = port_node.find("state")
                    if state_node is not None and state_node.get("state") != "open":
                        continue
                    try:
                        detected_port = int(port_node.get("portid", "0"))
                    except ValueError:
                        continue
                    service_node = port_node.find("service")
                    cpe_values = [
                        (node.text or "").strip()
                        for node in port_node.findall("service/cpe")
                        if (node.text or "").strip()
                    ]
                    nmap_rows.append({
                        "host": host,
                        "port": detected_port,
                        "protocol": (port_node.get("protocol") or "tcp").upper(),
                        "service_name": (
                            service_node.get("name")
                            if service_node is not None
                            else "unknown"
                        ) or "unknown",
                        "product": service_node.get("product") if service_node is not None else None,
                        "version": service_node.get("version") if service_node is not None else None,
                        "extra_info": service_node.get("extrainfo") if service_node is not None else None,
                        "tunnel": service_node.get("tunnel") if service_node is not None else None,
                        "cpes": cpe_values,
                    })
            complete_pipeline_stage("service_detection")

            httpx_result = run_command(
                [
                    str(tools["httpx"]),
                    "-l", str(hosts_file),
                    "-status-code", "-title", "-tech-detect", "-ip",
                    "-json", "-silent",
                    "-timeout", "10",
                    "-retries", "1",
                ],
                "httpx",
                300,
                stage="web_analysis",
            )
            complete_pipeline_stage("web_analysis")
            http_rows = parse_json_lines(httpx_result.stdout)
            urls = sorted({
                str(row.get("url", "")).strip()
                for row in http_rows
                if str(row.get("url", "")).startswith(("http://", "https://"))
            })

            technologies_by_host: dict[str, set[str]] = {}
            for row in http_rows:
                host = hostname_from(str(row.get("url") or row.get("input") or ""))
                if not host:
                    continue
                raw_technologies = row.get("tech") or []
                if isinstance(raw_technologies, str):
                    raw_technologies = [raw_technologies]
                technologies_by_host.setdefault(host, set()).update(
                    str(value).strip()
                    for value in raw_technologies
                    if str(value).strip()
                )

            if application_discovery_stage_enabled:
                set_pipeline_stage("application_discovery")
                discovered_urls, additional_technologies = collect_additional_urls(
                    target=target,
                    initial_urls=urls,
                    temp_path=temp_path,
                    tools=tools,
                    run_command=run_command,
                )
                for host, values in additional_technologies.items():
                    technologies_by_host.setdefault(host, set()).update(values)

                if discovered_urls:
                    extended_urls_file = temp_path / "extended-urls.txt"
                    extended_urls_file.write_text(
                        "\n".join(discovered_urls) + "\n",
                        encoding="utf-8",
                    )
                    extended_httpx_result = run_command(
                        [
                            str(tools["httpx"]),
                            "-l",
                            str(extended_urls_file),
                            "-status-code",
                            "-title",
                            "-tech-detect",
                            "-ip",
                            "-json",
                            "-silent",
                            "-timeout",
                            "10",
                            "-retries",
                            "1",
                            "-rate-limit",
                            "50",
                        ],
                        "discovered URL validation",
                        600,
                        continue_on_error=True,
                    )
                    merged_http_rows: dict[str, dict[str, Any]] = {}
                    for row in [*http_rows, *parse_json_lines(extended_httpx_result.stdout)]:
                        row_url = str(row.get("url") or "").strip()
                        if row_url:
                            merged_http_rows[row_url] = row
                    http_rows = list(merged_http_rows.values())

                complete_pipeline_stage("application_discovery")

            for row in http_rows:
                host = hostname_from(str(row.get("url") or row.get("input") or ""))
                if not host:
                    continue
                raw_technologies = row.get("tech") or []
                if isinstance(raw_technologies, str):
                    raw_technologies = [raw_technologies]
                technologies_by_host.setdefault(host, set()).update(
                    str(value).strip()
                    for value in raw_technologies
                    if str(value).strip()
                )

            urls = sorted({
                str(row.get("url", "")).strip()
                for row in http_rows
                if str(row.get("url", "")).startswith(("http://", "https://"))
            })

            specialized_vulnerability_rows: list[dict[str, Any]] = []
            secret_rows: list[dict[str, Any]] = []
            if specialized_stage_enabled:
                set_pipeline_stage("specialized_assessment")
                if urls:
                    (
                        specialized_vulnerability_rows,
                        secret_rows,
                        specialized_technologies,
                    ) = run_specialized_assessments(
                        target=target,
                        urls=urls,
                        technologies_by_host=technologies_by_host,
                        temp_path=temp_path,
                        tools=tools,
                        run_command=run_command,
                    )
                    for host, values in specialized_technologies.items():
                        technologies_by_host.setdefault(host, set()).update(values)
                complete_pipeline_stage("specialized_assessment")

            # Merge all factual technology labels into the HTTP rows that are
            # later persisted on each responsive subdomain.
            for row in http_rows:
                host = hostname_from(str(row.get("url") or row.get("input") or ""))
                if not host:
                    continue
                existing = row.get("tech") or []
                if isinstance(existing, str):
                    existing = [existing]
                merged = {str(value).strip() for value in existing if str(value).strip()}
                merged.update(technologies_by_host.get(host, set()))
                row["tech"] = sorted(merged)

            urls_file.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

            # Screenshots are captured once per responsive origin, not for every
            # archived/crawled path. This prevents endpoint discovery from
            # producing thousands of duplicate screenshots.
            screenshot_urls = sorted({
                f"{parsed.scheme}://{parsed.netloc}"
                for value in urls
                if (parsed := urlparse(value)).scheme in {"http", "https"}
                and parsed.netloc
            })[:100]
            screenshot_urls_file = temp_path / "screenshot-urls.txt"
            screenshot_urls_file.write_text(
                "\n".join(screenshot_urls) + ("\n" if screenshot_urls else ""),
                encoding="utf-8",
            )

            nuclei_rows: list[dict] = []
            set_pipeline_stage("vulnerability_analysis")
            if urls:
                template_dir = Path("/home/appuser/nuclei-templates")
                template_dir.mkdir(parents=True, exist_ok=True)
                if not any(template_dir.rglob("*.yaml")):
                    run_command(
                        [
                            str(tools["nuclei"]),
                            "-update-templates",
                            "-update-template-dir", str(template_dir),
                        ],
                        "nuclei template update",
                        420,
                        continue_on_error=True,
                    )
                if any(template_dir.rglob("*.yaml")):
                    nuclei_result = run_command(
                        [
                            str(tools["nuclei"]),
                            "-l", str(urls_file),
                            "-templates", str(template_dir),
                            "-severity", "critical,high,medium,low,info",
                            "-jsonl", "-silent",
                            "-timeout", "10",
                            "-retries", "1",
                            "-rate-limit", "100",
                            "-concurrency","35",
                            "-bulk-size","35",
                            "-disable-update-check",
                        ],
                        "nuclei",
                        settings.nuclei_scan_timeout_seconds,
                        continue_on_error=True,
                    )
                    # TimeoutExpired includes output produced before the process
                    # was stopped, so real findings are not discarded.
                    nuclei_rows = parse_json_lines(nuclei_result.stdout)
                else:
                    message = "nuclei skipped because no templates are available"
                    logger.warning(message)
                    pipeline_warnings.append(message)
            complete_pipeline_stage("vulnerability_analysis")

            gowitness_rows: list[dict] = []
            set_pipeline_stage("visual_capture")
            if screenshot_urls:
                run_command(
                    [
                        str(tools["gowitness"]),
                        "scan", "file",
                        "-f", str(screenshot_urls_file),
                        "-s", str(screenshot_dir),
                        "--write-jsonl",
                        "--write-jsonl-file", str(gowitness_jsonl),
                        "--chrome-path", str(chromium),
                        "-T", "15",
                        "-t", "4",
                    ],
                    "gowitness",
                    420,
                    continue_on_error=True,
                )
                if gowitness_jsonl.exists():
                    gowitness_rows = parse_json_lines(gowitness_jsonl.read_text(encoding="utf-8"))
            complete_pipeline_stage("visual_capture")

            _set_live_scan_state(
                scan.id,
                status="running",
                current_tool=None,
                progress=min(
                    99,
                    round(
                        stage_positions["visual_capture"]
                        * 100
                        / len(pipeline_stages)
                    ),
                ),
            )

            # Replace the prior enriched result set only after every scanner
            # command succeeds. Live subfinder rows above are factual partial
            # results and are safe to keep if a later stage fails.
            old_subdomain_ids = [
                row[0]
                for row in self.db.query(Subdomain.id).filter(Subdomain.domain_id == domain.id).all()
            ]
            if old_subdomain_ids:
                self.db.query(Subdomain).filter(Subdomain.id.in_(old_subdomain_ids)).delete(
                    synchronize_session=False
                )
            self.db.query(DNSRecord).filter(DNSRecord.domain_id == domain.id).delete(
                synchronize_session=False
            )
            self.db.flush()

            dns_by_host: dict[str, set[str]] = {}
            dns_records: set[tuple[str, str]] = set()
            for row in dns_rows:
                host = hostname_from(str(row.get("host") or row.get("input") or ""))
                if host:
                    hostnames.add(host)
                for key, record_type in (("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME")):
                    values = row.get(key) or []
                    if isinstance(values, str):
                        values = [values]
                    for raw_value in values:
                        value = str(raw_value).strip().rstrip(".")
                        if not value:
                            continue
                        dns_records.add((record_type, value))
                        if host and record_type in {"A", "AAAA"}:
                            dns_by_host.setdefault(host, set()).add(value)

            for row in port_rows:
                host = hostname_from(str(row.get("input") or row.get("host") or ""))
                if host:
                    hostnames.add(host)
                    if row.get("ip"):
                        dns_by_host.setdefault(host, set()).add(str(row["ip"]))
            for row in http_rows:
                host = hostname_from(str(row.get("url") or row.get("input") or ""))
                if host:
                    hostnames.add(host)
                    ip_value = row.get("a") or row.get("host_ip")
                    if isinstance(ip_value, list):
                        dns_by_host.setdefault(host, set()).update(str(value) for value in ip_value)
                    elif ip_value:
                        dns_by_host.setdefault(host, set()).add(str(ip_value))

            http_by_host = {
                hostname_from(str(row.get("url") or row.get("input") or "")): row
                for row in http_rows
                if hostname_from(str(row.get("url") or row.get("input") or ""))
            }

            subdomain_by_name: dict[str, Subdomain] = {}
            now = datetime.now(timezone.utc)
            for hostname in sorted(hostnames):
                http_row = http_by_host.get(hostname, {})
                url = str(http_row.get("url") or "")
                value = Subdomain(
                    domain_id=domain.id,
                    subdomain=hostname,
                    ip_addresses=json.dumps(sorted(dns_by_host.get(hostname, set()))),
                    is_responsive=bool(http_row),
                    response_status_code=http_row.get("status_code"),
                    has_ssl=url.startswith("https://"),
                    technologies=json.dumps(http_row.get("tech") or []),
                    last_checked=now,
                )
                self.db.add(value)
                self.db.flush()
                subdomain_by_name[hostname] = value

            for record_type, record_value in sorted(dns_records):
                self.db.add(DNSRecord(
                    domain_id=domain.id,
                    record_type=record_type,
                    record_value=record_value,
                ))

            seen_secret_rows: set[tuple[str, str, str]] = set()
            for row in secret_rows:
                host = hostname_from(str(row.get("host") or ""))
                subdomain = subdomain_by_name.get(host)
                secret_type = str(row.get("secret_type") or "CLIENT_SIDE_SECRET_PATTERN")[:100]
                location = str(row.get("location") or "")[:255]
                identity = (host, secret_type, location)
                if not subdomain or not location or identity in seen_secret_rows:
                    continue
                seen_secret_rows.add(identity)
                try:
                    confidence = float(row.get("confidence") or 0.0)
                except (TypeError, ValueError):
                    confidence = 0.0
                self.db.add(Secret(
                    subdomain_id=subdomain.id,
                    secret_type=secret_type,
                    secret_location=location,
                    confidence=max(0.0, min(1.0, confidence)),
                    is_active=True,
                ))

            service_by_host_port: dict[tuple[str, int], Service] = {}

            def ensure_service(
                host: str,
                port_number: int,
                protocol: str = "TCP",
                detected: Optional[dict[str, Any]] = None,
            ) -> Optional[Service]:
                subdomain = subdomain_by_name.get(host)
                if not subdomain or not port_number:
                    return None
                key = (host, int(port_number))
                if key in service_by_host_port:
                    return service_by_host_port[key]
                detected = detected or {}
                service_name = str(detected.get("service_name") or "").strip().lower()
                if not service_name:
                    service_name = (
                        "https" if int(port_number) == 443
                        else "http" if int(port_number) in {80, 8080, 8000, 3000}
                        else "ssh" if int(port_number) == 22
                        else "unknown"
                    )
                if detected.get("tunnel") == "ssl" and service_name == "http":
                    service_name = "https"
                port = Port(
                    subdomain_id=subdomain.id,
                    port_number=int(port_number),
                    protocol=protocol.upper(),
                    status="open",
                    service_name=service_name,
                )
                self.db.add(port)
                self.db.flush()
                service = Service(
                    port_id=port.id,
                    service_name=service_name,
                    product=(
                        str(detected["product"])[:255]
                        if detected.get("product")
                        else None
                    ),
                    version=(
                        str(detected["version"])[:100]
                        if detected.get("version")
                        else None
                    ),
                    confidence=0.9 if detected else (1.0 if service_name != "unknown" else 0.5),
                )
                self.db.add(service)
                self.db.flush()
                service_by_host_port[key] = service
                return service

            nmap_services_for_ai: list[dict[str, Any]] = []
            for row in nmap_rows:
                service = ensure_service(
                    row["host"],
                    row["port"],
                    row.get("protocol") or "TCP",
                    row,
                )
                if service:
                    nmap_services_for_ai.append({
                        "service_id": service.id,
                        "host": row["host"],
                        "port": row["port"],
                        "protocol": row.get("protocol") or "TCP",
                        "service_name": service.service_name,
                        "product": service.product,
                        "version": service.version,
                        "cpes": row.get("cpes") or [],
                    })

            for row in port_rows:
                host = hostname_from(str(row.get("input") or row.get("host") or ""))
                try:
                    port_number = int(row.get("port"))
                except (TypeError, ValueError):
                    continue
                ensure_service(host, port_number, str(row.get("proto") or "tcp"))

            for row in http_rows:
                url = str(row.get("url") or "")
                parsed_url = urlparse(url)
                host = (parsed_url.hostname or hostname_from(str(row.get("input") or ""))).lower()
                port_number = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                ensure_service(host, port_number)

            vulnerabilities_created = 0
            severity_risk = {"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 0}
            highest_risk = 0
            seen_vulnerabilities: set[tuple[str, str, str]] = set()

            for row in specialized_vulnerability_rows:
                matched_at = str(row.get("matched_at") or "")
                parsed_match = urlparse(
                    matched_at if "://" in matched_at else f"//{matched_at}"
                )
                host = (parsed_match.hostname or hostname_from(matched_at)).lower()
                port_number = parsed_match.port or (
                    443 if parsed_match.scheme == "https" else 80
                )
                service = ensure_service(host, port_number)
                if not service:
                    continue

                title = str(row.get("title") or "Security assessment finding")[:255]
                identity = (
                    str(row.get("cve_id") or ""),
                    matched_at,
                    title,
                )
                if identity in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add(identity)

                severity = str(row.get("severity") or "info").lower()
                if severity not in severity_risk:
                    severity = "info"
                raw_cvss = row.get("cvss_score")
                try:
                    cvss_score = float(raw_cvss) if raw_cvss is not None else None
                except (TypeError, ValueError):
                    cvss_score = None

                self.db.add(Vulnerability(
                    service_id=service.id,
                    cve_id=(str(row.get("cve_id"))[:50] if row.get("cve_id") else None),
                    title=title,
                    description=str(row.get("description") or "") or None,
                    severity=severity.capitalize(),
                    cvss_score=cvss_score,
                    cvss_vector=None,
                ))
                vulnerabilities_created += 1
                highest_risk = max(
                    highest_risk,
                    round(cvss_score * 10)
                    if cvss_score is not None
                    else severity_risk.get(severity, 0),
                )

            for row in nuclei_rows:
                info = row.get("info") or {}
                matched_at = str(row.get("matched-at") or row.get("host") or "")
                parsed_match = urlparse(matched_at if "://" in matched_at else f"//{matched_at}")
                host = (parsed_match.hostname or hostname_from(matched_at)).lower()
                port_number = parsed_match.port or (443 if parsed_match.scheme == "https" else 80)
                service = ensure_service(host, port_number)
                if not service:
                    continue

                template_id = str(row.get("template-id") or "")
                title = str(info.get("name") or template_id or "Nuclei finding")
                identity = (template_id, matched_at, title)
                if identity in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add(identity)

                severity = str(info.get("severity") or "info").lower()
                classification = info.get("classification") or {}
                cve_values = classification.get("cve-id") or []
                if isinstance(cve_values, str):
                    cve_values = [cve_values]
                cve_id = ", ".join(str(value).upper() for value in cve_values) or None
                raw_cvss = classification.get("cvss-score")
                if isinstance(raw_cvss, list):
                    raw_cvss = raw_cvss[0] if raw_cvss else None
                try:
                    cvss_score = float(raw_cvss) if raw_cvss is not None else None
                except (TypeError, ValueError):
                    cvss_score = None
                raw_vector = classification.get("cvss-metrics")
                if isinstance(raw_vector, list):
                    raw_vector = ", ".join(str(value) for value in raw_vector)

                self.db.add(Vulnerability(
                    service_id=service.id,
                    cve_id=cve_id[:50] if cve_id else None,
                    title=title,
                    description=info.get("description"),
                    severity=severity.capitalize(),
                    cvss_score=cvss_score,
                    cvss_vector=str(raw_vector)[:255] if raw_vector else None,
                ))
                vulnerabilities_created += 1
                highest_risk = max(
                    highest_risk,
                    round(cvss_score * 10) if cvss_score is not None else severity_risk.get(severity, 0),
                )

            screenshot_files = {
                path.name: path for path in screenshot_dir.rglob("*")
                if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}
            }
            for raw_row in gowitness_rows:
                row = raw_row.get("data") if isinstance(raw_row.get("data"), dict) else raw_row
                url = str(row.get("url") or row.get("final_url") or "")
                host = hostname_from(url)
                subdomain = subdomain_by_name.get(host)
                raw_file = (
                    row.get("screenshot")
                    or row.get("screenshot_path")
                    or row.get("file_name")
                    or row.get("filename")
                    or row.get("file")
                )
                file_path = None
                if raw_file:
                    candidate = Path(str(raw_file))
                    if not candidate.is_absolute():
                        candidate = screenshot_dir / candidate
                    if candidate.is_file():
                        file_path = candidate
                    elif candidate.name in screenshot_files:
                        file_path = screenshot_files[candidate.name]
                if not subdomain or not url or not file_path:
                    continue
                parsed_url = urlparse(url)
                self.db.add(Screenshot(
                    subdomain_id=subdomain.id,
                    url=url,
                    protocol=parsed_url.scheme,
                    port=parsed_url.port or (443 if parsed_url.scheme == "https" else 80),
                    file_path=str(file_path),
                    file_size=file_path.stat().st_size,
                    status_code=row.get("status_code") or row.get("response_code"),
                    title=row.get("title"),
                    is_valid=1,
                ))

            # Commit factual scanner output before optional external AI
            # enrichment. A Gemini outage must never discard Nmap/Nuclei data.
            self.db.commit()

            ai_actionable_count = 0
            if gemini_stage_enabled:
                set_pipeline_stage("ai_service_analysis")

            if gemini_stage_enabled and nmap_services_for_ai:
                try:
                    from app.services.gemini_service_assessment import (
                        GeminiServiceVersionAnalyzer,
                    )

                    analyzer = GeminiServiceVersionAnalyzer(self.db)
                    try:
                        ai_result = analyzer.analyze_and_persist(
                            scan.id,
                            nmap_services_for_ai,
                        )
                    finally:
                        analyzer.close()
                    ai_actionable_count = int(ai_result.get("actionable_count") or 0)
                    pipeline_warnings.extend(ai_result.get("warnings") or [])
                    logger.info(
                        "Gemini service-version analysis for scan %s assessed %s service(s); %s actionable",
                        scan.id,
                        int(ai_result.get("assessed_count") or 0),
                        ai_actionable_count,
                    )
                    for severity, count in (ai_result.get("severity_counts") or {}).items():
                        if count:
                            highest_risk = max(
                                highest_risk,
                                severity_risk.get(str(severity).lower(), 0),
                            )
                except Exception as exc:
                    # Scanner results are already committed. Roll back only the
                    # incomplete AI transaction and finish with a warning.
                    self.db.rollback()
                    logger.exception("Gemini service-version analysis failed")
                    pipeline_warnings.append(
                        f"Gemini service-version analysis failed: {str(exc)[:500]}"
                    )

            if gemini_stage_enabled:
                complete_pipeline_stage("ai_service_analysis")

            return {
                "discovered_count": len(subdomain_by_name),
                "vulnerable_count": vulnerabilities_created + ai_actionable_count,
                "risk_score": min(100, highest_risk),
                "warnings": pipeline_warnings,
            }
