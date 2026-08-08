"""
Tool Executor — runs real security tools via subprocess.
No mocks. No fake output. Real CLI execution only.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from sqlalchemy.orm import Session

from app.models.scan_models import ToolExecution, ScanLog
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

TOOLS_DIR = Path(settings.pd_tools_path)
SCREENSHOTS_DIR = Path(settings.screenshot_output_dir)


def _find_tool(name: str) -> Optional[str]:
    """Locate a tool binary: shutil.which → PD tools dir → common paths."""
    # Check system PATH first
    p = shutil.which(name)
    if p:
        return p
    # Check PD tools dir
    custom = TOOLS_DIR / name
    if custom.is_file():
        return str(custom)
    # Common install locations
    for base in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"]:
        candidate = Path(base) / name
        if candidate.is_file():
            return str(candidate)
    return None


async def _run_cmd(
    cmd: List[str],
    timeout: int = 300,
    env: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Execute a real CLI command asynchronously.
    Returns dict with stdout, stderr, exit_code, duration.
    """
    started = datetime.utcnow()
    logger.info(f"[exec] {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **(env or {})},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {
                "stdout":    "",
                "stderr":    f"Tool timed out after {timeout}s",
                "exit_code": -1,
                "duration":  timeout,
                "timed_out": True,
            }

        finished = datetime.utcnow()
        duration = int((finished - started).total_seconds())
        return {
            "stdout":    stdout_b.decode("utf-8", errors="replace"),
            "stderr":    stderr_b.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
            "duration":  duration,
            "timed_out": False,
        }
    except FileNotFoundError:
        return {
            "stdout":    "",
            "stderr":    f"Tool not found: {cmd[0]}",
            "exit_code": 127,
            "duration":  0,
            "timed_out": False,
        }
    except Exception as e:
        return {
            "stdout": "", "stderr": str(e),
            "exit_code": -1, "duration": 0, "timed_out": False,
        }


class ToolRunner:
    """
    Runs every security tool in the pipeline.
    Each method returns parsed structured output + raw output.
    """

    def __init__(self, db: Session, scan_job_id: str):
        self.db = db
        self.scan_job_id = scan_job_id

    def _log(self, message: str, level: str = "info", tool: str = ""):
        log = ScanLog(
            scan_job_id=self.scan_job_id,
            level=level, message=message, tool=tool,
            logged_at=datetime.utcnow(),
        )
        self.db.add(log)
        self.db.commit()

    def _save_tool_result(
        self,
        tool_exec: ToolExecution,
        result: Dict,
        parsed: Any,
        count: int = 0,
    ):
        tool_exec.exit_code       = result["exit_code"]
        tool_exec.raw_output      = result["stdout"][:50000]   # cap at 50KB
        tool_exec.error_output    = result["stderr"][:10000]
        tool_exec.parsed_output   = parsed if isinstance(parsed, (dict, list)) else None
        tool_exec.result_count    = count
        tool_exec.duration_seconds = result["duration"]
        tool_exec.finished_at     = datetime.utcnow()
        tool_exec.status = (
            "completed" if result["exit_code"] in (0, 1) else "failed"
        )
        if result["exit_code"] == 127:
            tool_exec.error_message = f"Tool not installed: {tool_exec.tool_name}"
            tool_exec.status = "skipped"
        self.db.commit()

    # ── 1. Subfinder — Subdomain discovery ────────────────────────

    async def run_subfinder(self, tool_exec: ToolExecution, target: str) -> List[str]:
        tool = _find_tool("subfinder")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "subfinder not installed"
            self.db.commit()
            self._log("subfinder not found — skipping", "warn", "subfinder")
            return []

        self._log(f"subfinder: enumerating subdomains for {target}", tool="subfinder")
        cmd = [tool, "-d", target, "-silent", "-json", "-timeout", "30"]
        result = await _run_cmd(cmd, timeout=180)

        subdomains = []
        for line in result["stdout"].splitlines():
            try:
                obj = json.loads(line.strip())
                host = obj.get("host", line.strip())
                if host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append(line.strip())

        subdomains = list(set(subdomains))
        self._save_tool_result(tool_exec, result, subdomains, len(subdomains))
        self._log(f"subfinder: found {len(subdomains)} subdomains", tool="subfinder")
        return subdomains

    # ── 2. DNSx — DNS resolution → IPs ───────────────────────────

    async def run_dnsx(self, tool_exec: ToolExecution, targets: List[str]) -> Dict[str, List[str]]:
        tool = _find_tool("dnsx")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "dnsx not installed" if not tool else None
            self.db.commit()
            return {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name

        try:
            cmd = [tool, "-l", tmp, "-a", "-resp", "-json", "-silent", "-retry", "2"]
            result = await _run_cmd(cmd, timeout=120)
            ip_map: Dict[str, List[str]] = {}
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    host = obj.get("host", "")
                    ips  = obj.get("a", [])
                    if host and ips:
                        ip_map[host] = ips
                except json.JSONDecodeError:
                    pass
            self._save_tool_result(tool_exec, result, ip_map, len(ip_map))
            self._log(f"dnsx: resolved {len(ip_map)} hosts", tool="dnsx")
            return ip_map
        finally:
            os.unlink(tmp)

    # ── 3. HTTPx — Live host detection + tech detection ───────────

    async def run_httpx(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict]:
        tool = _find_tool("httpx")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "httpx not installed" if not tool else None
            self.db.commit()
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name

        try:
            cmd = [
                tool, "-l", tmp, "-json", "-silent",
                "-status-code", "-title", "-tech-detect",
                "-ip", "-content-length", "-follow-redirects",
                "-timeout", "10", "-threads", "50",
            ]
            result = await _run_cmd(cmd, timeout=300)
            probes = []
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
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
                        "cdn":         obj.get("cdn", False),
                    })
                except json.JSONDecodeError:
                    pass
            self._save_tool_result(tool_exec, result, probes, len(probes))
            self._log(f"httpx: {len(probes)} live hosts", tool="httpx")
            return probes
        finally:
            os.unlink(tmp)

    # ── 4. Naabu — Port scanning ──────────────────────────────────

    async def run_naabu(self, tool_exec: ToolExecution, targets: List[str]) -> Dict[str, List[int]]:
        tool = _find_tool("naabu")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "naabu not installed" if not tool else None
            self.db.commit()
            return {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name

        try:
            cmd = [
                tool, "-list", tmp, "-json", "-silent",
                "-top-ports", "1000", "-timeout", "5000",
                "-retries", "2", "-rate", "1000",
            ]
            result = await _run_cmd(cmd, timeout=600)
            port_map: Dict[str, List[int]] = {}
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    ip   = obj.get("ip", obj.get("host", ""))
                    port = obj.get("port")
                    if ip and port:
                        port_map.setdefault(ip, []).append(int(port))
                except (json.JSONDecodeError, ValueError):
                    pass
            self._save_tool_result(tool_exec, result, port_map, sum(len(v) for v in port_map.values()))
            self._log(f"naabu: found open ports on {len(port_map)} hosts", tool="naabu")
            return port_map
        finally:
            os.unlink(tmp)

    # ── 5. Nmap — Service & OS detection ─────────────────────────

    async def run_nmap(self, tool_exec: ToolExecution, targets: List[str], ports: List[str]) -> List[Dict]:
        tool = _find_tool("nmap")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "nmap not installed" if not tool else None
            self.db.commit()
            return []

        port_str = ",".join(str(p) for p in ports[:200]) if ports else "80,443,8080,8443,21,22,23,25,53,110,143,3306,5432,6379,27017"
        target_str = " ".join(targets[:50])

        cmd = [
            tool, "-sV", "-O", "--open",
            "-p", port_str,
            "-oX", "-",
            "--max-retries", "1",
            "--host-timeout", "120s",
        ] + targets[:50]

        result = await _run_cmd(cmd, timeout=600)

        # Parse Nmap XML output
        services = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result["stdout"])
            for host_el in root.findall(".//host"):
                addr_el = host_el.find("address")
                ip = addr_el.get("addr", "") if addr_el is not None else ""
                for port_el in host_el.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        svc_el = port_el.find("service")
                        services.append({
                            "ip":       ip,
                            "port":     int(port_el.get("portid", 0)),
                            "protocol": port_el.get("protocol", "tcp"),
                            "service":  svc_el.get("name", "") if svc_el is not None else "",
                            "product":  svc_el.get("product", "") if svc_el is not None else "",
                            "version":  svc_el.get("version", "") if svc_el is not None else "",
                        })
        except Exception as e:
            self._log(f"nmap XML parse error: {e}", "warn", "nmap")

        self._save_tool_result(tool_exec, result, services, len(services))
        self._log(f"nmap: {len(services)} open services detected", tool="nmap")
        return services

    # ── 6. Katana — Web crawler ───────────────────────────────────

    async def run_katana(self, tool_exec: ToolExecution, targets: List[str]) -> List[str]:
        tool = _find_tool("katana")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "katana not installed" if not tool else None
            self.db.commit()
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets[:20]))
            tmp = f.name

        try:
            cmd = [
                tool, "-list", tmp, "-silent", "-json",
                "-depth", "3", "-jc", "-kf", "all",
                "-timeout", "10", "-c", "20",
            ]
            result = await _run_cmd(cmd, timeout=300)
            urls = []
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    ep = obj.get("endpoint", obj.get("request", {}).get("endpoint", ""))
                    if ep:
                        urls.append(ep)
                except json.JSONDecodeError:
                    if line.strip().startswith("http"):
                        urls.append(line.strip())
            urls = list(set(urls))
            self._save_tool_result(tool_exec, result, urls, len(urls))
            self._log(f"katana: crawled {len(urls)} URLs", tool="katana")
            return urls
        finally:
            os.unlink(tmp)

    # ── 7. Nuclei — Vulnerability scanning ───────────────────────

    async def run_nuclei(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict]:
        tool = _find_tool("nuclei")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "nuclei not installed" if not tool else None
            self.db.commit()
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets[:100]))
            tmp = f.name

        try:
            cmd = [
                tool, "-list", tmp, "-json", "-silent",
                "-severity", "critical,high,medium,low",
                "-timeout", "10", "-rate-limit", "50",
                "-bulk-size", "25", "-concurrency", "25",
                "-etags", "dos",   # skip DoS templates
            ]
            if settings.pdcp_api_key:
                cmd += ["-auth"]

            result = await _run_cmd(cmd, timeout=1200)
            findings = []
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    info = obj.get("info", {})
                    classification = info.get("classification", {})
                    findings.append({
                        "template_id":  obj.get("template-id", ""),
                        "title":        info.get("name", ""),
                        "severity":     info.get("severity", "info"),
                        "description":  info.get("description", ""),
                        "cvss_score":   classification.get("cvss-score"),
                        "cvss_vector":  classification.get("cvss-metrics", ""),
                        "cve_id":       ",".join(classification.get("cve-id", [])),
                        "cwe_id":       ",".join(classification.get("cwe-id", [])),
                        "tags":         info.get("tags", []),
                        "references":   info.get("reference", []),
                        "host":         obj.get("host", ""),
                        "url":          obj.get("matched-at", obj.get("host", "")),
                        "matched_at":   obj.get("matched-at", ""),
                        "http_request": obj.get("request", ""),
                        "http_response": obj.get("response", ""),
                        "evidence":     obj.get("extracted-results", []),
                        "curl_command": obj.get("curl-command", ""),
                    })
                except json.JSONDecodeError:
                    pass
            self._save_tool_result(tool_exec, result, findings, len(findings))
            self._log(f"nuclei: {len(findings)} vulnerabilities found", tool="nuclei")
            return findings
        finally:
            os.unlink(tmp)

    # ── 8. Dirsearch — Directory enumeration ─────────────────────

    async def run_dirsearch(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict]:
        tool = _find_tool("dirsearch")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "dirsearch not installed" if not tool else None
            self.db.commit()
            return []

        self._log(f"dirsearch: scanning {len(targets)} targets", tool="dirsearch")
        all_results = []

        for target in targets[:5]:  # limit to first 5 live hosts
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                out_file = f.name

            cmd = [
                tool, "-u", target,
                "--format", "json", "-o", out_file,
                "-q", "-t", "20",
                "-x", "400,404,500,502,503",
                "--timeout", "10",
                "-R", "2",  # recursion depth
            ]
            result = await _run_cmd(cmd, timeout=300)

            try:
                if os.path.exists(out_file):
                    with open(out_file) as jf:
                        data = json.load(jf)
                    results_key = target if target in data else list(data.keys())[0] if data else None
                    if results_key:
                        for item in data[results_key]:
                            all_results.append({
                                "url":    item.get("url", ""),
                                "status": item.get("status", 0),
                                "size":   item.get("content-length", 0),
                                "type":   item.get("type", ""),
                                "redirect": item.get("redirect", ""),
                            })
            except Exception as e:
                self._log(f"dirsearch parse error: {e}", "warn", "dirsearch")
            finally:
                if os.path.exists(out_file):
                    os.unlink(out_file)

        self._save_tool_result(tool_exec, {"stdout": "", "stderr": "", "exit_code": 0, "duration": 0}, all_results, len(all_results))
        self._log(f"dirsearch: {len(all_results)} paths found", tool="dirsearch")
        return all_results

    # ── 9. XSStrike — XSS scanning ───────────────────────────────

    async def run_xsstrike(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict]:
        tool = _find_tool("xsstrike") or _find_tool("XSStrike")
        xsstrike_py = shutil.which("xsstrike") or "/opt/XSStrike/xsstrike.py"

        if not (tool or os.path.exists(xsstrike_py)):
            tool_exec.status = "skipped"
            tool_exec.error_message = "XSStrike not installed"
            self.db.commit()
            self._log("XSStrike not found — skipping", "warn", "xsstrike")
            return []

        # XSStrike needs URL with parameter — filter targets with query params
        param_targets = [t for t in targets if "?" in t and "=" in t]
        if not param_targets:
            self._log("XSStrike: no parameterized URLs to test", "info", "xsstrike")
            tool_exec.status = "completed"
            tool_exec.result_count = 0
            self.db.commit()
            return []

        findings = []
        for target in param_targets[:10]:
            py_cmd = ["python3", xsstrike_py, "-u", target, "--blind", "--timeout", "10"]
            bin_cmd = [tool, "-u", target, "--blind", "--timeout", "10"] if tool else None
            cmd = bin_cmd or py_cmd

            result = await _run_cmd(cmd, timeout=120)
            # XSStrike outputs to stdout — look for "XSS" markers
            for line in result["stdout"].splitlines():
                if "xss" in line.lower() or "payload" in line.lower() or "vulnerable" in line.lower():
                    findings.append({
                        "url":      target,
                        "evidence": line.strip(),
                        "source":   "xsstrike",
                    })

        self._save_tool_result(
            tool_exec,
            {"stdout": "", "stderr": "", "exit_code": 0, "duration": 0},
            findings, len(findings)
        )
        self._log(f"XSStrike: {len(findings)} XSS indicators", tool="xsstrike")
        return findings

    # ── 10. Gowitness — Screenshots ───────────────────────────────

    async def run_gowitness(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict]:
        tool = _find_tool("gowitness")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "gowitness not installed" if not tool else None
            self.db.commit()
            return []

        out_dir = SCREENSHOTS_DIR / self.scan_job_id
        out_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(out_dir / "gowitness.db")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets[:50]))
            tmp = f.name

        try:
            cmd = [
                tool, "scan", "file",
                "-f", tmp,
                "--db-uri", f"sqlite:///{db_path}",
                "--screenshot-path", str(out_dir),
                "--threads", "5",
                "--timeout", "20",
            ]
            result = await _run_cmd(cmd, timeout=600)

            screenshots = []
            for img in out_dir.glob("*.png"):
                screenshots.append({
                    "file_path": str(img),
                    "url":       img.stem.replace("_", "://", 1),
                    "size":      img.stat().st_size,
                })
            self._save_tool_result(tool_exec, result, screenshots, len(screenshots))
            self._log(f"gowitness: {len(screenshots)} screenshots captured", tool="gowitness")
            return screenshots
        finally:
            os.unlink(tmp)

    # ── 11. ASNMap — ASN/CIDR Mapping ────────────────────────────

    async def run_asnmap(self, tool_exec: ToolExecution, target: str) -> List[str]:
        tool = _find_tool("asnmap")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "asnmap not installed"
            self.db.commit()
            self._log("asnmap not found — skipping", "warn", "asnmap")
            return []
        self._log(f"asnmap: mapping ASN/CIDRs for {target}", tool="asnmap")
        cmd = [tool, "-a", target, "-silent", "-json"] if target.lower().startswith("as") else [tool, "-d", target, "-silent", "-json"]
        result = await _run_cmd(cmd, timeout=120)
        cidrs = []
        for line in result["stdout"].splitlines():
            try:
                obj = json.loads(line.strip())
                cidr = obj.get("cidr", "")
                if cidr:
                    cidrs.append(cidr)
            except json.JSONDecodeError:
                if line.strip():
                    cidrs.append(line.strip())
        self._save_tool_result(tool_exec, result, cidrs, len(cidrs))
        self._log(f"asnmap: resolved {len(cidrs)} CIDRs", tool="asnmap")
        return cidrs

    # ── 12. MapCIDR — CIDR Expansion ─────────────────────────────

    async def run_mapcidr(self, tool_exec: ToolExecution, targets: List[str]) -> List[str]:
        tool = _find_tool("mapcidr")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "mapcidr not installed" if not tool else None
            self.db.commit()
            return []
        self._log(f"mapcidr: expanding CIDRs", tool="mapcidr")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name
        try:
            cmd = [tool, "-l", tmp, "-silent"]
            result = await _run_cmd(cmd, timeout=120)
            ips = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            self._save_tool_result(tool_exec, result, ips, len(ips))
            self._log(f"mapcidr: expanded to {len(ips)} IPs", tool="mapcidr")
            return ips
        finally:
            os.unlink(tmp)

    # ── 13. CDNCheck — CDN/WAF detection ─────────────────────────

    async def run_cdncheck(self, tool_exec: ToolExecution, targets: List[str]) -> Dict[str, Any]:
        tool = _find_tool("cdncheck")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "cdncheck not installed" if not tool else None
            self.db.commit()
            return {}
        self._log(f"cdncheck: verifying CDN/WAF status", tool="cdncheck")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name
        try:
            cmd = [tool, "-l", tmp, "-resp", "-json", "-silent"]
            result = await _run_cmd(cmd, timeout=120)
            results = {}
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    ip = obj.get("ip", "")
                    if ip:
                        results[ip] = {
                            "cdn": obj.get("cdn", False),
                            "cdn_name": obj.get("cdn_name", ""),
                            "waf": obj.get("waf", False),
                            "waf_name": obj.get("waf_name", ""),
                            "cloud": obj.get("cloud", False),
                            "cloud_name": obj.get("cloud_name", ""),
                        }
                except json.JSONDecodeError:
                    pass
            self._save_tool_result(tool_exec, result, results, len(results))
            self._log(f"cdncheck: processed {len(results)} targets", tool="cdncheck")
            return results
        finally:
            os.unlink(tmp)

    # ── 14. TLSx — SSL/TLS Handshake ─────────────────────────────

    async def run_tlsx(self, tool_exec: ToolExecution, targets: List[str]) -> List[Dict[str, Any]]:
        tool = _find_tool("tlsx")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "tlsx not installed" if not tool else None
            self.db.commit()
            return []
        self._log(f"tlsx: fetching SSL/TLS certificates", tool="tlsx")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name
        try:
            cmd = [tool, "-l", tmp, "-json", "-silent", "-retry", "1", "-ex"]
            result = await _run_cmd(cmd, timeout=300)
            certs = []
            for line in result["stdout"].splitlines():
                try:
                    obj = json.loads(line.strip())
                    certs.append({
                        "host": obj.get("host", ""),
                        "ip": obj.get("ip", ""),
                        "subject_dn": obj.get("subject_dn", ""),
                        "issuer_dn": obj.get("issuer_dn", ""),
                        "serial_number": obj.get("serial_number", ""),
                        "not_before": obj.get("not_before", ""),
                        "not_after": obj.get("not_after", ""),
                        "emails": obj.get("emails", []),
                        "dns_names": obj.get("dns_names", []),
                        "tls_version": obj.get("tls_version", ""),
                        "cipher": obj.get("cipher", ""),
                    })
                except json.JSONDecodeError:
                    pass
            self._save_tool_result(tool_exec, result, certs, len(certs))
            self._log(f"tlsx: gathered certificates for {len(certs)} hosts", tool="tlsx")
            return certs
        finally:
            os.unlink(tmp)

    # ── 15. Alterx — Permutation Generator ───────────────────────

    async def run_alterx(self, tool_exec: ToolExecution, targets: List[str]) -> List[str]:
        tool = _find_tool("alterx")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "alterx not installed" if not tool else None
            self.db.commit()
            return []
        self._log(f"alterx: generating subdomain permutations", tool="alterx")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name
        try:
            cmd = [tool, "-l", tmp, "-silent", "-limit", "500"]
            result = await _run_cmd(cmd, timeout=180)
            perms = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            self._save_tool_result(tool_exec, result, perms, len(perms))
            self._log(f"alterx: generated {len(perms)} permutations", tool="alterx")
            return perms
        finally:
            os.unlink(tmp)

    # ── 16. Uncover — Search Engine Query ────────────────────────

    async def run_uncover(self, tool_exec: ToolExecution, query: str) -> List[str]:
        tool = _find_tool("uncover")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "uncover not installed"
            self.db.commit()
            self._log("uncover not found — skipping", "warn", "uncover")
            return []
        self._log(f"uncover: searching passive engines for query '{query}'", tool="uncover")
        env = {}
        if settings.shodan_api_key:
            env["SHODAN_API_KEY"] = settings.shodan_api_key
        cmd = [tool, "-q", query, "-silent", "-limit", "100"]
        result = await _run_cmd(cmd, timeout=120, env=env)
        hosts = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
        self._save_tool_result(tool_exec, result, hosts, len(hosts))
        self._log(f"uncover: found {len(hosts)} hosts", tool="uncover")
        return hosts

    # ── 17. ShuffleDNS — Subdomain Resolving ─────────────────────

    async def run_shuffledns(self, tool_exec: ToolExecution, domain: str, subdomains: List[str]) -> List[str]:
        tool = _find_tool("shuffledns")
        if not tool or not subdomains:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "shuffledns not installed" if not tool else None
            self.db.commit()
            return []
        self._log(f"shuffledns: mass dns resolution for {domain}", tool="shuffledns")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as list_f:
            list_f.write("\n".join(subdomains))
            list_tmp = list_f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as r_f:
            r_f.write("1.1.1.1\n8.8.8.8\n9.9.9.9\n")
            r_tmp = r_f.name
        try:
            cmd = [tool, "-d", domain, "-list", list_tmp, "-r", r_tmp, "-silent"]
            result = await _run_cmd(cmd, timeout=300)
            resolved = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            self._save_tool_result(tool_exec, result, resolved, len(resolved))
            self._log(f"shuffledns: resolved {len(resolved)} subdomains", tool="shuffledns")
            return resolved
        finally:
            os.unlink(list_tmp)
            os.unlink(r_tmp)

    # ── 18. URLFinder — Scrape JS URLs ───────────────────────────

    async def run_urlfinder(self, tool_exec: ToolExecution, targets: List[str]) -> List[str]:
        tool = _find_tool("urlfinder")
        if not tool or not targets:
            tool_exec.status = "skipped" if not tool else "completed"
            tool_exec.error_message = "urlfinder not installed" if not tool else None
            self.db.commit()
            return []
        self._log(f"urlfinder: extracting urls", tool="urlfinder")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name
        try:
            cmd = [tool, "-list", tmp, "-silent"]
            result = await _run_cmd(cmd, timeout=300)
            urls = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            self._save_tool_result(tool_exec, result, urls, len(urls))
            self._log(f"urlfinder: extracted {len(urls)} URLs", tool="urlfinder")
            return urls
        finally:
            os.unlink(tmp)

    # ── 19. Notify — Dispatch Alert ──────────────────────────────

    async def run_notify(self, tool_exec: ToolExecution, message: str) -> bool:
        tool = _find_tool("notify")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "notify not installed"
            self.db.commit()
            return False
        if not settings.slack_webhook_url:
            tool_exec.status = "skipped"
            tool_exec.error_message = "slack_webhook_url not configured"
            self.db.commit()
            return False
        self._log(f"notify: sending notification", tool="notify")
        config_content = f"slack:\n  - id: \"slack\"\n    slack_webhook_url: \"{settings.slack_webhook_url}\"\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_tmp = f.name
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, "-config", config_tmp, "-silent",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_b, stderr_b = await proc.communicate(input=message.encode("utf-8"))
            result = {
                "exit_code": proc.returncode,
                "stdout": stdout_b.decode("utf-8", errors="replace"),
                "stderr": stderr_b.decode("utf-8", errors="replace"),
                "duration": 5,
            }
            self._save_tool_result(tool_exec, result, result["stdout"], 1)
            self._log(f"notify: alert dispatched successfully", tool="notify")
            return proc.returncode == 0
        finally:
            os.unlink(config_tmp)

    # ── 20. Proxify — Local Proxy Client ─────────────────────────

    async def run_proxify(self, tool_exec: ToolExecution) -> str:
        tool = _find_tool("proxify")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "proxify not installed"
            self.db.commit()
            return ""
        self._log(f"proxify: running CLI verification", tool="proxify")
        cmd = [tool, "-version"]
        result = await _run_cmd(cmd, timeout=30)
        self._save_tool_result(tool_exec, result, result["stdout"].strip(), 1)
        return result["stdout"].strip()

    # ── 21. Interactsh Client — OOB Testing ──────────────────────

    async def run_interactsh(self, tool_exec: ToolExecution) -> str:
        tool = _find_tool("interactsh-client")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "interactsh-client not installed"
            self.db.commit()
            return ""
        self._log(f"interactsh: registering temporary client URL", tool="interactsh")
        cmd = [tool, "-n", "1", "-silent"]
        result = await _run_cmd(cmd, timeout=30)
        url = result["stdout"].strip()
        self._save_tool_result(tool_exec, result, url, 1 if url else 0)
        self._log(f"interactsh: client URL registered: {url}", tool="interactsh")
        return url

    # ── 22. Chaos — Chaos Dataset Subdomains ─────────────────────

    async def run_chaos(self, tool_exec: ToolExecution, target: str) -> List[str]:
        tool = _find_tool("chaos")
        if not tool:
            tool_exec.status = "skipped"
            tool_exec.error_message = "chaos not installed"
            self.db.commit()
            self._log("chaos not found — skipping", "warn", "chaos")
            return []
        self._log(f"chaos: fetching Chaos dataset subdomains for {target}", tool="chaos")
        env = {}
        if settings.chaos_api_key:
            env["CHAOS_KEY"] = settings.chaos_api_key
        elif settings.pdcp_api_key:
            env["PDCP_API_KEY"] = settings.pdcp_api_key
        cmd = [tool, "-d", target, "-silent", "-json"]
        result = await _run_cmd(cmd, timeout=120, env=env)
        subdomains = []
        for line in result["stdout"].splitlines():
            try:
                obj = json.loads(line.strip())
                subdomains.append(obj.get("subdomain", line.strip()))
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append(line.strip())
        self._save_tool_result(tool_exec, result, subdomains, len(subdomains))
        self._log(f"chaos: found {len(subdomains)} subdomains", tool="chaos")
        return subdomains
