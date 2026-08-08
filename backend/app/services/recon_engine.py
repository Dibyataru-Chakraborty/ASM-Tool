"""
ProjectDiscovery Recon Engine
Uses Go-based tools via subprocess:
  - subfinder  : subdomain discovery
  - dnsx       : DNS resolution → exact IPs
  - naabu      : port scanning
  - httpx      : HTTP probing + screenshots
  - nuclei     : vulnerability scanning
  - gowitness  : full-page screenshots
Docs: https://docs.projectdiscovery.io/opensource
"""

import asyncio
import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.config import settings
from app.models.subdomain import Subdomain
from app.models.domain import Domain
from app.models.phase2 import Port, Service, Technology
from app.models.screenshot import Screenshot
from app.models.phases_4_to_10 import Vulnerability
from app.utils.logger import get_logger

logger = get_logger(__name__)

TOOLS = {
    "subfinder": "subfinder",
    "dnsx":      "dnsx",
    "naabu":     "naabu",
    "httpx":     "httpx",
    "nuclei":    "nuclei",
    "gowitness": "gowitness",
    "nmap":      "nmap",
}


def _tool_path(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    custom = os.path.join(settings.pd_tools_path, name)
    if os.path.isfile(custom):
        return custom
    raise FileNotFoundError(
        f"Tool '{name}' not found. Install from https://docs.projectdiscovery.io/opensource"
    )


def _run(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Run a subprocess and return stdout lines as list."""
    try:
        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return {"success": True, "lines": lines, "stderr": result.stderr}
    except FileNotFoundError as e:
        logger.error(str(e))
        return {"success": False, "lines": [], "error": str(e)}
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout running {cmd[0]}")
        return {"success": False, "lines": [], "error": "timeout"}
    except Exception as e:
        logger.error(f"Error running {cmd[0]}: {e}")
        return {"success": False, "lines": [], "error": str(e)}


class SubfinderEngine:
    """Subdomain discovery using subfinder."""

    def discover(self, domain: str, silent: bool = True) -> List[str]:
        """Return list of discovered subdomains."""
        try:
            tool = _tool_path("subfinder")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return []

        cmd = [tool, "-d", domain, "-silent", "-json"]
        if settings.pdcp_api_key:
            cmd += ["-provider-config", "/root/.config/subfinder/provider-config.yaml"]

        result = _run(cmd, timeout=120)
        subdomains = []
        for line in result["lines"]:
            try:
                obj = json.loads(line)
                subdomains.append(obj.get("host", line))
            except json.JSONDecodeError:
                subdomains.append(line)

        logger.info(f"subfinder found {len(subdomains)} subdomains for {domain}")
        return list(set(subdomains))


class DNSXEngine:
    """DNS resolution using dnsx — returns exact IP list per subdomain."""

    def resolve(self, subdomains: List[str]) -> Dict[str, List[str]]:
        """Returns {subdomain: [ip1, ip2, ...]} mapping."""
        if not subdomains:
            return {}
        try:
            tool = _tool_path("dnsx")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            tmp_path = f.name

        try:
            cmd = [tool, "-l", tmp_path, "-a", "-resp", "-json", "-silent"]
            result = _run(cmd, timeout=120)
            ip_map: Dict[str, List[str]] = {}
            for line in result["lines"]:
                try:
                    obj = json.loads(line)
                    host = obj.get("host", "")
                    ips = obj.get("a", [])
                    if host and ips:
                        ip_map[host] = ips
                except json.JSONDecodeError:
                    pass
            logger.info(f"dnsx resolved {len(ip_map)} subdomains")
            return ip_map
        finally:
            os.unlink(tmp_path)


class NaabuEngine:
    """Port scanning using naabu."""

    def scan(self, targets: List[str], ports: str = "top-100") -> Dict[str, List[int]]:
        """Returns {host: [port1, port2, ...]} mapping."""
        if not targets:
            return {}
        try:
            tool = _tool_path("naabu")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp_path = f.name

        try:
            cmd = [
                tool, "-list", tmp_path,
                "-top-ports", "100",
                "-silent", "-json",
                "-timeout", "5000",
            ]
            result = _run(cmd, timeout=300)
            port_map: Dict[str, List[int]] = {}
            for line in result["lines"]:
                try:
                    obj = json.loads(line)
                    ip = obj.get("ip", obj.get("host", ""))
                    port = obj.get("port")
                    if ip and port:
                        port_map.setdefault(ip, []).append(int(port))
                except (json.JSONDecodeError, ValueError):
                    pass
            logger.info(f"naabu found open ports on {len(port_map)} hosts")
            return port_map
        finally:
            os.unlink(tmp_path)


class HTTPXEngine:
    """HTTP probing using httpx."""

    def probe(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Returns list of HTTP probe results with status, title, tech, etc."""
        if not targets:
            return []
        try:
            tool = _tool_path("httpx")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp_path = f.name

        try:
            cmd = [
                tool, "-l", tmp_path,
                "-json", "-silent",
                "-status-code", "-title",
                "-tech-detect", "-ip",
                "-content-length", "-follow-redirects",
                "-timeout", "10",
            ]
            result = _run(cmd, timeout=300)
            probes = []
            for line in result["lines"]:
                try:
                    obj = json.loads(line)
                    probes.append({
                        "url":         obj.get("url", ""),
                        "host":        obj.get("host", ""),
                        "ip":          obj.get("ip", ""),
                        "status_code": obj.get("status_code", 0),
                        "title":       obj.get("title", ""),
                        "technologies": obj.get("tech", []),
                        "content_length": obj.get("content_length", 0),
                        "webserver":   obj.get("webserver", ""),
                        "tls":         obj.get("tls", {}),
                    })
                except json.JSONDecodeError:
                    pass
            logger.info(f"httpx probed {len(probes)} live hosts")
            return probes
        finally:
            os.unlink(tmp_path)


class NucleiEngine:
    """Vulnerability scanning using nuclei."""

    def scan(
        self,
        targets: List[str],
        severity: str = "critical,high,medium",
        templates: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns list of nuclei findings."""
        if not targets:
            return []
        try:
            tool = _tool_path("nuclei")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp_path = f.name

        try:
            cmd = [
                tool, "-list", tmp_path,
                "-json", "-silent",
                "-severity", severity,
                "-timeout", "10",
                "-rate-limit", "50",
            ]
            if templates:
                cmd += ["-t", templates]
            if settings.pdcp_api_key:
                cmd += ["-auth"]

            result = _run(cmd, timeout=600)
            findings = []
            for line in result["lines"]:
                try:
                    obj = json.loads(line)
                    findings.append({
                        "template_id":   obj.get("template-id", ""),
                        "name":          obj.get("info", {}).get("name", ""),
                        "severity":      obj.get("info", {}).get("severity", "info").capitalize(),
                        "description":   obj.get("info", {}).get("description", ""),
                        "host":          obj.get("host", ""),
                        "matched_at":    obj.get("matched-at", ""),
                        "cvss_score":    obj.get("info", {}).get("classification", {}).get("cvss-score"),
                        "cve_id":        ",".join(obj.get("info", {}).get("classification", {}).get("cve-id", [])),
                        "tags":          obj.get("info", {}).get("tags", []),
                    })
                except json.JSONDecodeError:
                    pass
            logger.info(f"nuclei found {len(findings)} vulnerabilities")
            return findings
        finally:
            os.unlink(tmp_path)


class GoWitnessEngine:
    """Full-page screenshots using gowitness."""

    def screenshot(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Takes screenshots and returns list of {url, path} dicts."""
        if not targets:
            return []
        try:
            tool = _tool_path("gowitness")
        except FileNotFoundError as e:
            logger.warning(str(e))
            return []

        out_dir = Path(settings.screenshot_output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(out_dir / "gowitness.db")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp_path = f.name

        try:
            cmd = [
                tool, "scan", "file",
                "-f", tmp_path,
                "--db-uri", f"sqlite:///{db_path}",
                "--screenshot-path", str(out_dir),
                "--threads", str(settings.screenshot_threads),
                "--timeout", str(settings.screenshot_timeout),
                "--disable-db=false",
            ]
            _run(cmd, timeout=600)

            # Collect screenshots
            screenshots = []
            for img in out_dir.glob("*.png"):
                url = img.stem.replace("_", "://", 1).replace("_", "/")
                screenshots.append({
                    "url":  url,
                    "path": str(img),
                    "size": img.stat().st_size,
                })
            logger.info(f"gowitness captured {len(screenshots)} screenshots")
            return screenshots
        finally:
            os.unlink(tmp_path)


class FullReconEngine:
    """
    Orchestrates all ProjectDiscovery tools for complete recon:
    1. subfinder  → subdomains
    2. dnsx       → IPs per subdomain
    3. naabu      → open ports per IP
    4. httpx      → HTTP probe + tech detection
    5. nuclei     → vulnerabilities
    6. gowitness  → screenshots
    """

    def __init__(self, db: Session):
        self.db = db
        self.subfinder = SubfinderEngine()
        self.dnsx      = DNSXEngine()
        self.naabu     = NaabuEngine()
        self.httpx     = HTTPXEngine()
        self.nuclei    = NucleiEngine()
        self.gowitness = GoWitnessEngine()

    async def run_full_recon(
        self,
        domain: str,
        asset_id: str,
        domain_id: str,
    ) -> Dict[str, Any]:
        """Run full recon pipeline and save all results to DB."""

        logger.info(f"Starting full recon for {domain}")
        report: Dict[str, Any] = {
            "domain":       domain,
            "started_at":   datetime.utcnow().isoformat(),
            "subdomains":   [],
            "ip_map":       {},
            "ports":        {},
            "http_probes":  [],
            "vulnerabilities": [],
            "screenshots":  [],
        }

        # ── Step 1: Subdomain enumeration ────────────────────────
        logger.info(f"[1/6] subfinder — {domain}")
        subs = await asyncio.to_thread(self.subfinder.discover, domain)
        report["subdomains"] = subs
        logger.info(f"Found {len(subs)} subdomains")

        # Save subdomains to DB
        saved_subs = []
        for sub in subs:
            db_sub = Subdomain(
                domain_id=domain_id,
                subdomain=sub,
                is_responsive=False,
                has_ssl=False,
                ip_addresses=[],
            )
            self.db.add(db_sub)
            saved_subs.append(db_sub)
        self.db.commit()

        # ── Step 2: DNS resolution → IPs ─────────────────────────
        logger.info(f"[2/6] dnsx — resolving {len(subs)} subdomains")
        ip_map = await asyncio.to_thread(self.dnsx.resolve, subs)
        report["ip_map"] = ip_map

        # Update subdomains with IPs
        for sub_obj in saved_subs:
            ips = ip_map.get(sub_obj.subdomain, [])
            sub_obj.ip_addresses = ips
        self.db.commit()

        # Build unique IP list for port scanning
        all_ips = list({ip for ips in ip_map.values() for ip in ips})
        logger.info(f"Resolved {len(all_ips)} unique IPs: {all_ips[:10]}{'...' if len(all_ips) > 10 else ''}")

        # ── Step 3: Port scanning ─────────────────────────────────
        logger.info(f"[3/6] naabu — scanning {len(all_ips)} IPs")
        port_map = await asyncio.to_thread(self.naabu.scan, all_ips)
        report["ports"] = port_map

        # Save ports to DB
        for sub_obj in saved_subs:
            for ip in ip_map.get(sub_obj.subdomain, []):
                for port_num in port_map.get(ip, []):
                    db_port = Port(
                        subdomain_id=sub_obj.id,
                        port_number=port_num,
                        protocol="TCP",
                        status="open",
                    )
                    self.db.add(db_port)
        self.db.commit()

        # ── Step 4: HTTP probing ──────────────────────────────────
        http_targets = [f"http://{s}" for s in subs] + [f"https://{s}" for s in subs]
        logger.info(f"[4/6] httpx — probing {len(subs)} hosts")
        probes = await asyncio.to_thread(self.httpx.probe, subs)
        report["http_probes"] = probes

        # Update subdomains with HTTP data + save technologies
        for probe in probes:
            host = probe["host"]
            for sub_obj in saved_subs:
                if sub_obj.subdomain == host:
                    sub_obj.is_responsive = probe["status_code"] > 0
                    sub_obj.has_ssl = probe["url"].startswith("https")
                    # Save technologies
                    for tech in probe.get("technologies", []):
                        db_tech = Technology(
                            subdomain_id=sub_obj.id,
                            technology_name=tech,
                            confidence=0.9,
                        )
                        self.db.add(db_tech)
        self.db.commit()

        # ── Step 5: Nuclei vulnerability scan ─────────────────────
        live_targets = [p["url"] for p in probes if p.get("url")]
        logger.info(f"[5/6] nuclei — scanning {len(live_targets)} live targets")
        findings = await asyncio.to_thread(self.nuclei.scan, live_targets)
        report["vulnerabilities"] = findings

        # Save vulnerabilities to DB
        for finding in findings:
            db_vuln = Vulnerability(
                title=finding["name"] or finding["template_id"],
                description=finding.get("description", ""),
                severity=finding.get("severity", "Info"),
                cve_id=finding.get("cve_id") or None,
                cvss_score=finding.get("cvss_score"),
            )
            self.db.add(db_vuln)
        self.db.commit()

        # ── Step 6: Screenshots ───────────────────────────────────
        logger.info(f"[6/6] gowitness — screenshotting {len(live_targets)} targets")
        shots = await asyncio.to_thread(self.gowitness.screenshot, live_targets)
        report["screenshots"] = shots

        # Save screenshot records
        for shot in shots:
            for sub_obj in saved_subs:
                if sub_obj.subdomain in shot["url"]:
                    db_shot = Screenshot(
                        subdomain_id=sub_obj.id,
                        url=shot["url"],
                        file_path=shot["path"],
                        status_code=200,
                    )
                    self.db.add(db_shot)
        self.db.commit()

        report["finished_at"] = datetime.utcnow().isoformat()
        report["summary"] = {
            "subdomains_found":    len(subs),
            "unique_ips":          len(all_ips),
            "open_port_hosts":     len(port_map),
            "live_http_hosts":     len(probes),
            "vulnerabilities":     len(findings),
            "screenshots_taken":   len(shots),
        }
        logger.info(f"Full recon complete: {report['summary']}")
        return report

    def get_all_ips(self, domain_id: str) -> List[Dict[str, Any]]:
        """Return all unique IPs for a domain (subdomains resolved)."""
        subs = self.db.query(Subdomain).filter(
            Subdomain.domain_id == domain_id
        ).all()
        ip_list = []
        seen = set()
        for sub in subs:
            for ip in (sub.ip_addresses or []):
                if ip not in seen:
                    seen.add(ip)
                    ip_list.append({
                        "ip":        ip,
                        "subdomain": sub.subdomain,
                        "has_ssl":   sub.has_ssl,
                    })
        return ip_list

    def get_all_subdomains(self, domain_id: str) -> List[Dict[str, Any]]:
        """Return all subdomains with IPs, ports, and tech stack."""
        subs = self.db.query(Subdomain).filter(
            Subdomain.domain_id == domain_id
        ).all()
        return [
            {
                "subdomain":    s.subdomain,
                "ip_addresses": s.ip_addresses or [],
                "is_responsive": s.is_responsive,
                "has_ssl":      s.has_ssl,
                "ports":        [p.port_number for p in s.ports] if hasattr(s, "ports") else [],
                "technologies": [t.technology_name for t in s.technologies] if hasattr(s, "technologies") else [],
                "screenshots":  [sc.file_path for sc in s.screenshots] if hasattr(s, "screenshots") else [],
            }
            for s in subs
        ]
