"""
Scanner Pipeline
Runs every tool sequentially. Next tool starts only after previous completes.
Saves raw + parsed output for every tool. Stores all findings in DB.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional

from sqlalchemy.orm import Session

from app.models.scan_models import (
    ScanJob, ToolExecution, VulnFinding, ScanLog, ASMAsset
)
from app.services.tool_executor import ToolRunner
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Tool pipeline definition — order matters
PIPELINE: List[Dict[str, Any]] = [
    {"name": "asnmap",      "label": "ASN/CIDR Mapping",        "timeout": 120,  "order": 1},
    {"name": "chaos",       "label": "Chaos Subdomain Fetch",   "timeout": 120,  "order": 2},
    {"name": "uncover",     "label": "Passive Search Engines",  "timeout": 120,  "order": 3},
    {"name": "subfinder",   "label": "Subdomain Enumeration",   "timeout": 180,  "order": 4},
    {"name": "alterx",      "label": "Subdomain Permutation",   "timeout": 180,  "order": 5},
    {"name": "shuffledns",  "label": "Mass Subdomain Resolving","timeout": 300,  "order": 6},
    {"name": "dnsx",        "label": "DNS Resolution",          "timeout": 120,  "order": 7},
    {"name": "cdncheck",    "label": "CDN/WAF Check",           "timeout": 120,  "order": 8},
    {"name": "mapcidr",     "label": "CIDR Range Expansion",    "timeout": 120,  "order": 9},
    {"name": "httpx",       "label": "Live Host Detection",     "timeout": 300,  "order": 10},
    {"name": "tlsx",        "label": "SSL/TLS Certification",   "timeout": 300,  "order": 11},
    {"name": "naabu",       "label": "Port Scanning",           "timeout": 600,  "order": 12},
    {"name": "nmap",        "label": "Service Detection",       "timeout": 600,  "order": 13},
    {"name": "katana",      "label": "Web Crawling",            "timeout": 300,  "order": 14},
    {"name": "urlfinder",   "label": "JS URL Scraper",          "timeout": 300,  "order": 15},
    {"name": "dirsearch",   "label": "Directory Enumeration",   "timeout": 300,  "order": 16},
    {"name": "nuclei",      "label": "Vulnerability Scanning",  "timeout": 1200, "order": 17},
    {"name": "xsstrike",    "label": "XSS Scanning",            "timeout": 300,  "order": 18},
    {"name": "interactsh",  "label": "Interactsh Client Setup",  "timeout": 60,   "order": 19},
    {"name": "gowitness",   "label": "Screenshot Capture",      "timeout": 600,  "order": 20},
    {"name": "proxify",     "label": "Proxy Verification",      "timeout": 60,   "order": 21},
    {"name": "notify",      "label": "Alert Dispatches",        "timeout": 60,   "order": 22},
]

StatusCallback = Callable[[str, int, str], None]  # (status, progress%, current_tool)


class ScanPipeline:
    """
    Orchestrates the full scan pipeline for one asset.
    All results are real — no mocks.
    """

    def __init__(self, db: Session, scan_job_id: str,
                 on_progress: Optional[StatusCallback] = None):
        self.db           = db
        self.scan_job_id  = scan_job_id
        self.runner       = ToolRunner(db, scan_job_id)
        self.on_progress  = on_progress or (lambda s, p, t: None)

    def _log(self, msg: str, level: str = "info", tool: str = ""):
        log = ScanLog(
            scan_job_id=self.scan_job_id,
            level=level, message=msg, tool=tool,
            logged_at=datetime.utcnow(),
        )
        self.db.add(log)
        self.db.commit()
        logger.info(f"[{self.scan_job_id}] {msg}")

    def _update_job(self, status: str, progress: int, current_tool: str = ""):
        job = self.db.get(ScanJob, self.scan_job_id)
        if job:
            job.status       = status
            job.progress     = progress
            job.current_tool = current_tool
            self.db.commit()
        self.on_progress(status, progress, current_tool)

    def _create_tool_exec(self, tool_def: Dict) -> ToolExecution:
        te = ToolExecution(
            scan_job_id=self.scan_job_id,
            tool_name=tool_def["name"],
            order_index=tool_def["order"],
            status="running",
            started_at=datetime.utcnow(),
        )
        self.db.add(te)
        self.db.commit()
        self.db.refresh(te)
        return te

    def _save_vuln(self, finding: Dict, source_tool: str, asset_id: str):
        """Save a real vulnerability finding to DB."""
        sev = finding.get("severity", "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"

        vuln = VulnFinding(
            scan_job_id=self.scan_job_id,
            asset_id=asset_id,
            title=finding.get("title", "Unknown")[:512],
            severity=sev,
            cvss_score=finding.get("cvss_score"),
            cvss_vector=finding.get("cvss_vector", ""),
            cve_id=finding.get("cve_id", "") or None,
            cwe_id=finding.get("cwe_id", "") or None,
            template_id=finding.get("template_id", ""),
            url=finding.get("url", finding.get("matched_at", ""))[:2000],
            host=finding.get("host", "")[:255],
            description=finding.get("description", ""),
            recommendation=finding.get("recommendation", ""),
            references=finding.get("references", []),
            tags=finding.get("tags", []),
            http_request=finding.get("http_request", "")[:5000],
            http_response=finding.get("http_response", "")[:5000],
            proof_of_concept=finding.get("curl_command", ""),
            raw_evidence=str(finding.get("evidence", "")),
            source_tool=source_tool,
        )
        self.db.add(vuln)
        self.db.commit()

    async def run(self, asset: ASMAsset) -> Dict[str, Any]:
        """
        Execute the full pipeline for an asset.
        Returns summary dict.
        """
        target = asset.target
        asset_id = asset.id

        self._log(f"Pipeline started for {target}")
        self._update_job("running", 0, "starting")

        # Pipeline state — accumulated across tools
        state: Dict[str, Any] = {
            "subdomains": [],
            "ip_map": {},
            "live_hosts": [],
            "all_ips": [],
            "port_map": {},
            "all_ports_flat": [],
            "services": [],
            "crawled_urls": [],
            "dir_results": [],
            "vuln_count": 0,
            "xss_count": 0,
            "screenshots": [],
            "cidrs": [],
            "cdn_results": {},
            "certificates": [],
            "permutations": [],
            "uncover_hosts": [],
            "shuffledns_subdomains": [],
            "urlfinder_urls": [],
            "interactsh_url": "",
        }

        total_tools = len(PIPELINE)

        for idx, tool_def in enumerate(PIPELINE):
            tool_name = tool_def["name"]
            progress  = int(((idx) / total_tools) * 90)

            self._update_job("running", progress, tool_name)
            self._log(f"Starting {tool_def['label']}", tool=tool_name)

            te = self._create_tool_exec(tool_def)
            te.command = f"{tool_name} [target: {target}]"
            self.db.commit()

            try:
                # ── asnmap ────────────────────────────────────────
                if tool_name == "asnmap":
                    cidrs = await self.runner.run_asnmap(te, target)
                    state["cidrs"] = cidrs

                # ── chaos ─────────────────────────────────────────
                elif tool_name == "chaos":
                    if asset.asset_type == "domain":
                        chaos_subs = await self.runner.run_chaos(te, target)
                        state["subdomains"] = list(set(state["subdomains"] + chaos_subs))
                    else:
                        te.status = "skipped"
                        te.error_message = "Asset is not a domain"
                        self.db.commit()

                # ── uncover ───────────────────────────────────────
                elif tool_name == "uncover":
                    if asset.asset_type == "domain":
                        uncover_hosts = await self.runner.run_uncover(te, f"domain:{target}")
                        state["uncover_hosts"] = uncover_hosts
                    else:
                        te.status = "skipped"
                        te.error_message = "Asset is not a domain"
                        self.db.commit()

                # ── subfinder ─────────────────────────────────────
                elif tool_name == "subfinder":
                    if asset.asset_type == "domain":
                        subs = await self.runner.run_subfinder(te, target)
                        state["subdomains"] = list(set(state["subdomains"] + subs))
                    else:
                        te.status = "skipped"
                        te.error_message = "Asset is not a domain"
                        self.db.commit()

                # ── alterx ────────────────────────────────────────
                elif tool_name == "alterx":
                    if state["subdomains"]:
                        perms = await self.runner.run_alterx(te, state["subdomains"][:50])
                        state["permutations"] = perms
                    else:
                        te.status = "skipped"
                        te.error_message = "No subdomains found to permute"
                        self.db.commit()

                # ── shuffledns ────────────────────────────────────
                elif tool_name == "shuffledns":
                    sub_list = state["subdomains"] + state["permutations"]
                    if asset.asset_type == "domain" and sub_list:
                        shuf_subs = await self.runner.run_shuffledns(te, target, sub_list[:200])
                        state["subdomains"] = list(set(state["subdomains"] + shuf_subs))
                    else:
                        te.status = "skipped"
                        te.error_message = "No subdomains/permutations available or target not domain"
                        self.db.commit()

                # ── dnsx ──────────────────────────────────────────
                elif tool_name == "dnsx":
                    dns_targets = state["subdomains"] or [target]
                    ip_map = await self.runner.run_dnsx(te, dns_targets[:200])
                    state["ip_map"] = ip_map
                    state["all_ips"] = list({ip for ips in ip_map.values() for ip in ips})

                # ── cdncheck ──────────────────────────────────────
                elif tool_name == "cdncheck":
                    check_targets = state["all_ips"] or [target]
                    cdn_results = await self.runner.run_cdncheck(te, check_targets[:100])
                    state["cdn_results"] = cdn_results

                # ── mapcidr ───────────────────────────────────────
                elif tool_name == "mapcidr":
                    cidr_targets = state["cidrs"]
                    if cidr_targets:
                        expanded_ips = await self.runner.run_mapcidr(te, cidr_targets[:5])
                        state["all_ips"] = list(set(state["all_ips"] + expanded_ips))
                    else:
                        te.status = "skipped"
                        te.error_message = "No CIDRs mapped"
                        self.db.commit()

                # ── httpx ─────────────────────────────────────────
                elif tool_name == "httpx":
                    http_targets = state["subdomains"] or [target]
                    probes = await self.runner.run_httpx(te, http_targets[:100])
                    state["live_hosts"] = probes
                    all_techs = list({
                        t for p in probes for t in p.get("technologies", [])
                    })
                    state["technologies"] = all_techs

                # ── tlsx ──────────────────────────────────────────
                elif tool_name == "tlsx":
                    tls_targets = [h["host"] for h in state["live_hosts"] if h.get("host")]
                    if not tls_targets:
                        tls_targets = state["subdomains"] or [target]
                    certs = await self.runner.run_tlsx(te, tls_targets[:50])
                    state["certificates"] = certs

                # ── naabu ─────────────────────────────────────────
                elif tool_name == "naabu":
                    scan_targets = state["all_ips"] or [target]
                    port_map = await self.runner.run_naabu(te, scan_targets[:50])
                    state["port_map"] = port_map
                    state["all_ports_flat"] = list({
                        p for ports in port_map.values() for p in ports
                    })

                # ── nmap ──────────────────────────────────────────
                elif tool_name == "nmap":
                    nmap_targets = state["all_ips"] or [target]
                    services = await self.runner.run_nmap(
                        te, nmap_targets[:20], state["all_ports_flat"][:50]
                    )
                    state["services"] = services

                # ── katana ────────────────────────────────────────
                elif tool_name == "katana":
                    katana_targets = [h["url"] for h in state["live_hosts"] if h.get("url")]
                    if not katana_targets:
                        katana_targets = [f"http://{target}", f"https://{target}"]
                    urls = await self.runner.run_katana(te, katana_targets[:10])
                    state["crawled_urls"] = urls

                # ── urlfinder ─────────────────────────────────────
                elif tool_name == "urlfinder":
                    find_targets = [h["url"] for h in state["live_hosts"] if h.get("url")]
                    if not find_targets:
                        find_targets = [f"https://{target}"]
                    found_urls = await self.runner.run_urlfinder(te, find_targets[:10])
                    state["urlfinder_urls"] = found_urls
                    state["crawled_urls"] = list(set(state["crawled_urls"] + found_urls))

                # ── dirsearch ─────────────────────────────────────
                elif tool_name == "dirsearch":
                    dir_targets = [h["url"] for h in state["live_hosts"] if h.get("url")]
                    if not dir_targets:
                        dir_targets = [f"https://{target}"]
                    dirs = await self.runner.run_dirsearch(te, dir_targets[:3])
                    state["dir_results"] = dirs

                # ── nuclei ────────────────────────────────────────
                elif tool_name == "nuclei":
                    nuclei_targets = [h["url"] for h in state["live_hosts"] if h.get("url")]
                    nuclei_targets += state["crawled_urls"][:20]
                    if not nuclei_targets:
                        nuclei_targets = [f"https://{target}"]
                    nuclei_targets = list(set(nuclei_targets))

                    findings = await self.runner.run_nuclei(te, nuclei_targets[:30])
                    for f in findings:
                        self._save_vuln(f, "nuclei", asset_id)
                    state["vuln_count"] += len(findings)

                # ── xsstrike ──────────────────────────────────────
                elif tool_name == "xsstrike":
                    param_urls = [u for u in state["crawled_urls"] if "?" in u and "=" in u]
                    if not param_urls:
                        te.status = "skipped"
                        te.error_message = "No parameterized URLs found to test"
                        self.db.commit()
                        continue

                    xss_hits = await self.runner.run_xsstrike(te, param_urls[:10])
                    for hit in xss_hits:
                        self._save_vuln({
                            "title":       "Potential XSS Detected",
                            "severity":    "high",
                            "description": hit.get("evidence", ""),
                            "url":         hit.get("url", ""),
                            "source_tool": "xsstrike",
                        }, "xsstrike", asset_id)
                    state["xss_count"] += len(xss_hits)

                # ── interactsh ────────────────────────────────────
                elif tool_name == "interactsh":
                    interact_url = await self.runner.run_interactsh(te)
                    state["interactsh_url"] = interact_url

                # ── gowitness ─────────────────────────────────────
                elif tool_name == "gowitness":
                    shot_targets = [h["url"] for h in state["live_hosts"] if h.get("url")]
                    if not shot_targets:
                        shot_targets = [f"https://{target}"]
                    shots = await self.runner.run_gowitness(te, shot_targets[:20])
                    state["screenshots"] = shots

                # ── proxify ───────────────────────────────────────
                elif tool_name == "proxify":
                    await self.runner.run_proxify(te)

                # ── notify ────────────────────────────────────────
                elif tool_name == "notify":
                    msg = f"Attack Surface Management Scan Completed for {target}. Total vulnerabilities/issues detected: {state['vuln_count'] + state['xss_count']}"
                    await self.runner.run_notify(te, msg)

            except Exception as e:
                self._log(f"{tool_name} failed: {e}", "error", tool_name)
                te.status = "failed"
                te.error_message = str(e)[:500]
                te.finished_at = datetime.utcnow()
                self.db.commit()
                # Continue with next tool regardless of failure
                continue

        # ── Done ──────────────────────────────────────────────────
        total_vulns = state["vuln_count"] + state["xss_count"]
        self._update_job("completed", 95, "report")
        self._log(f"Pipeline complete: {total_vulns} vulnerabilities found")

        # Update asset last_scanned
        asset.last_scanned_at = datetime.utcnow()
        self.db.commit()

        return {
            "subdomains":     state["subdomains"],
            "live_hosts":     len(state["live_hosts"]),
            "unique_ips":     len(state["all_ips"]),
            "open_ports":     len(state["all_ports_flat"]),
            "services":       len(state["services"]),
            "crawled_urls":   len(state["crawled_urls"]),
            "vulnerabilities": total_vulns,
            "screenshots":    len(state["screenshots"]),
            "technologies":   state.get("technologies", []),
            "ip_map":         state["ip_map"],
            "port_map":       state["port_map"],
        }
