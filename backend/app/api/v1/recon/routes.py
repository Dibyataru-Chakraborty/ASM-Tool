"""
Recon API Routes — works standalone (no DB FKs required).
All recon runs against a live target URL/domain directly.
"""
from __future__ import annotations

import asyncio
import subprocess
import tempfile
import json
import os
import shutil
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, Query
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session
from app.models import Asset, Domain

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/recon", tags=["recon"])

# In-memory scan store for standalone recon jobs
_recon_jobs: dict = {}


@router.get("/assets")
async def get_recon_assets(
    request: Request,
    organization_id: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve assets mapped to their primary domain entries for recon selection."""
    org_id = organization_id or request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin" or (current_user.role == "admin" and current_user.tenant_id is not None):
        org_id = current_user.tenant_id

    q = db.query(Asset)
    if org_id:
        q = q.filter(Asset.tenant_id == org_id)
    else:
        q = q.filter(Asset.user_id == current_user.id)
    assets = q.all()

    items = []
    for asset in assets:
        domain = db.query(Domain).filter(Domain.asset_id == asset.id).first()
        items.append({
            "asset_id": asset.id,
            "asset_name": asset.name,
            "domain_id": domain.id if domain else None,
            "domain": domain.domain if domain else (asset.name),
            "active_scan_id": None
        })
    return {"items": items}


# ── Request schemas ───────────────────────────────────────────────────────────

class ReconStartRequest(BaseModel):
    target: str                        # domain, IP, URL — just the target
    run_tools: Optional[List[str]] = None  # if None, run all available tools

    @validator("target")
    def validate_target(cls, v):
        blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
        for b in blocked:
            if b in v:
                raise ValueError(f"Character '{b}' is not allowed in target")
        return v

class EnrichIPRequest(BaseModel):
    ip: str

    @validator("ip")
    def validate_ip(cls, v):
        blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
        for b in blocked:
            if b in v:
                raise ValueError(f"Character '{b}' is not allowed in IP")
        return v

class EnrichDomainRequest(BaseModel):
    domain: str

    @validator("domain")
    def validate_domain(cls, v):
        blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
        for b in blocked:
            if b in v:
                raise ValueError(f"Character '{b}' is not allowed in domain")
        return v

class AIAnalyzeRequest(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str = "Medium"
    cvss_score: Optional[float] = None
    affected_service: Optional[str] = None


# ── Tool helpers ──────────────────────────────────────────────────────────────

def _tool(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p: return p
    custom = os.path.join(settings.pd_tools_path, name)
    if os.path.isfile(custom): return custom
    return None


def _run(cmd: list, timeout: int = 120) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": True, "stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout", "code": -1}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": f"{cmd[0]} not found", "code": 127}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "code": -1}


# ── Background recon runner ────────────────────────────────────────────────────

async def _run_recon(job_id: str, target: str):
    """Run all available PD tools against target. No DB required."""
    _recon_jobs[job_id] = {
        "job_id": job_id, "target": target, "status": "running",
        "step": "starting", "subdomains": [], "ips": [], "ports": {},
        "live_hosts": [], "technologies": [], "vulnerabilities": [],
        "screenshots": [], "dir_results": [], "logs": [],
    }

    def log(msg):
        _recon_jobs[job_id]["logs"].append(msg)
        logger.info(f"[recon:{job_id}] {msg}")

    def update(step, **kwargs):
        _recon_jobs[job_id]["step"] = step
        _recon_jobs[job_id].update(kwargs)

    try:
        # ── subfinder ─────────────────────────────────────────────────────
        update("subfinder")
        log(f"subfinder: enumerating subdomains for {target}")
        tool = _tool("subfinder")
        subdomains = []
        if tool:
            r = await asyncio.to_thread(_run, [tool, "-d", target, "-silent", "-json"], 120)
            for line in r["stdout"].splitlines():
                try:
                    obj = json.loads(line)
                    sub = obj.get("host", line.strip())
                    if sub: subdomains.append(sub)
                except Exception:
                    if line.strip(): subdomains.append(line.strip())
            subdomains = list(set(subdomains))
            log(f"subfinder: found {len(subdomains)} subdomains")
        else:
            subdomains = [target]
            log("subfinder not installed — using target as-is")
        update("subfinder_done", subdomains=subdomains)

        # ── dnsx ──────────────────────────────────────────────────────────
        update("dnsx")
        log(f"dnsx: resolving {len(subdomains)} subdomains to IPs")
        ip_map = {}
        tool = _tool("dnsx")
        if tool and subdomains:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(subdomains)); tmp = f.name
            try:
                r = await asyncio.to_thread(_run, [tool, "-l", tmp, "-a", "-resp", "-json", "-silent"], 120)
                for line in r["stdout"].splitlines():
                    try:
                        obj = json.loads(line)
                        host = obj.get("host", "")
                        ips  = obj.get("a", [])
                        if host and ips: ip_map[host] = ips
                    except Exception: pass
            finally:
                os.unlink(tmp)
        all_ips = list({ip for ips in ip_map.values() for ip in ips})
        log(f"dnsx: resolved {len(all_ips)} unique IPs")
        update("dnsx_done", ips=all_ips)

        # ── httpx ─────────────────────────────────────────────────────────
        update("httpx")
        log(f"httpx: probing {len(subdomains)} hosts")
        live_hosts = []
        techs = []
        tool = _tool("httpx")
        if tool and subdomains:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(subdomains)); tmp = f.name
            try:
                r = await asyncio.to_thread(_run, [
                    tool, "-l", tmp, "-json", "-silent",
                    "-status-code", "-title", "-tech-detect", "-ip",
                    "-timeout", "10", "-threads", "50",
                ], 300)
                for line in r["stdout"].splitlines():
                    try:
                        obj = json.loads(line)
                        live_hosts.append({
                            "url":    obj.get("url", ""),
                            "host":   obj.get("host", ""),
                            "ip":     obj.get("ip", ""),
                            "status": obj.get("status_code", 0),
                            "title":  obj.get("title", ""),
                            "tech":   obj.get("tech", []),
                        })
                        techs.extend(obj.get("tech", []))
                    except Exception: pass
            finally:
                os.unlink(tmp)
        techs = list(set(techs))
        log(f"httpx: {len(live_hosts)} live hosts, {len(techs)} technologies")
        update("httpx_done", live_hosts=live_hosts, technologies=techs)

        # ── naabu ─────────────────────────────────────────────────────────
        update("naabu")
        log(f"naabu: port scanning {len(all_ips)} IPs")
        port_map = {}
        tool = _tool("naabu")
        if tool and all_ips:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(all_ips)); tmp = f.name
            try:
                r = await asyncio.to_thread(_run, [
                    tool, "-list", tmp, "-json", "-silent",
                    "-top-ports", "100", "-timeout", "3000",
                ], 300)
                for line in r["stdout"].splitlines():
                    try:
                        obj = json.loads(line)
                        ip   = obj.get("ip", obj.get("host", ""))
                        port = obj.get("port")
                        if ip and port: port_map.setdefault(ip, []).append(int(port))
                    except Exception: pass
            finally:
                os.unlink(tmp)
        log(f"naabu: found ports on {len(port_map)} hosts")
        update("naabu_done", ports=port_map)

        # ── nuclei ────────────────────────────────────────────────────────
        update("nuclei")
        nuclei_targets = [h["url"] for h in live_hosts if h.get("url")]
        if not nuclei_targets:
            nuclei_targets = [f"https://{target}", f"http://{target}"]
        log(f"nuclei: scanning {len(nuclei_targets)} targets")
        vulns = []
        tool = _tool("nuclei")
        if tool:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(nuclei_targets[:50])); tmp = f.name
            try:
                r = await asyncio.to_thread(_run, [
                    tool, "-list", tmp, "-json", "-silent",
                    "-severity", "critical,high,medium,low",
                    "-timeout", "10", "-rate-limit", "50",
                    "-etags", "dos",
                ], 600)
                for line in r["stdout"].splitlines():
                    try:
                        obj = json.loads(line)
                        info = obj.get("info", {})
                        cls  = info.get("classification", {})
                        vulns.append({
                            "template_id": obj.get("template-id", ""),
                            "title":       info.get("name", ""),
                            "severity":    info.get("severity", "info"),
                            "description": info.get("description", ""),
                            "cvss_score":  cls.get("cvss-score"),
                            "cve_id":      ",".join(cls.get("cve-id", [])),
                            "host":        obj.get("host", ""),
                            "url":         obj.get("matched-at", ""),
                            "curl":        obj.get("curl-command", ""),
                            "request":     obj.get("request", ""),
                        })
                    except Exception: pass
            finally:
                os.unlink(tmp)
        log(f"nuclei: {len(vulns)} vulnerabilities found")
        update("nuclei_done", vulnerabilities=vulns)

        # ── gowitness ─────────────────────────────────────────────────────
        update("gowitness")
        log(f"gowitness: capturing screenshots for {len(nuclei_targets)} targets")
        screenshots = []
        tool = _tool("gowitness")
        out_dir = os.path.join(settings.screenshot_output_dir, job_id)
        os.makedirs(out_dir, exist_ok=True)
        if tool:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(nuclei_targets[:30])); tmp = f.name
            try:
                await asyncio.to_thread(_run, [
                    tool, "scan", "file", "-f", tmp,
                    "--db-uri", f"sqlite:///{out_dir}/gowitness.db",
                    "--screenshot-path", out_dir,
                    "--threads", "5", "--timeout", "15",
                ], 300)
                from pathlib import Path
                for img in Path(out_dir).glob("*.png"):
                    screenshots.append({"file": str(img), "size": img.stat().st_size})
                log(f"gowitness: {len(screenshots)} screenshots")
            except Exception as e:
                log(f"gowitness error: {e}")
            finally:
                os.unlink(tmp)
        update("done", screenshots=screenshots, status="completed")

    except Exception as e:
        logger.error(f"[recon:{job_id}] Fatal: {e}")
        _recon_jobs[job_id].update({"status": "failed", "error": str(e)})


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_recon(
    req: ReconStartRequest,
    bg: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    """Start full recon on any domain/IP. No asset_id or domain_id needed."""
    import uuid
    job_id = str(uuid.uuid4())[:8]
    _recon_jobs[job_id] = {"job_id": job_id, "target": req.target, "status": "queued"}
    bg.add_task(_run_recon, job_id, req.target)
    return {"job_id": job_id, "status": "queued", "target": req.target,
            "message": f"Recon started. Poll /recon/status/{job_id}"}


@router.get("/status/{job_id}")
async def get_recon_status(job_id: str, current_user=Depends(get_current_user)):
    """Poll recon job status and results."""
    if job_id not in _recon_jobs:
        raise HTTPException(404, "Job not found")
    return _recon_jobs[job_id]


@router.get("/jobs")
async def list_recon_jobs(current_user=Depends(get_current_user)):
    return {"jobs": list(_recon_jobs.values())}


@router.get("/subdomains")
async def get_subdomains(job_id: str, current_user=Depends(get_current_user)):
    """Get subdomains from a completed recon job."""
    if job_id not in _recon_jobs:
        raise HTTPException(404, "Job not found")
    job = _recon_jobs[job_id]
    subs = job.get("subdomains", [])
    ip_map = {}
    for sub in subs:
        ips_found = []
        for live in job.get("live_hosts", []):
            if live.get("host") == sub:
                ip = live.get("ip")
                if ip: ips_found.append(ip)
        ip_map[sub] = ips_found
    return {"total": len(subs), "subdomains": [
        {"subdomain": s, "ip_addresses": ip_map.get(s, [])} for s in subs
    ]}


@router.get("/ips")
async def get_ips(job_id: str, current_user=Depends(get_current_user)):
    """Get unique IPs from a completed recon job."""
    if job_id not in _recon_jobs:
        raise HTTPException(404, "Job not found")
    job = _recon_jobs[job_id]
    all_ips = job.get("ips", [])
    sub_map: dict = {}
    for live in job.get("live_hosts", []):
        ip = live.get("ip", "")
        host = live.get("host", "")
        if ip and host:
            sub_map.setdefault(ip, []).append(host)
    return {"total_unique_ips": len(all_ips), "ips": [
        {"ip": ip, "subdomains": sub_map.get(ip, [])} for ip in all_ips
    ]}


@router.get("/screenshots")
async def get_screenshots(job_id: str, current_user=Depends(get_current_user)):
    """Get screenshots from a completed recon job."""
    if job_id not in _recon_jobs:
        raise HTTPException(404, "Job not found")
    shots = _recon_jobs[job_id].get("screenshots", [])
    return {"total": len(shots), "screenshots": shots}


@router.get("/vulnerabilities")
async def get_vulns(job_id: str, current_user=Depends(get_current_user)):
    """Get vulnerabilities found during recon."""
    if job_id not in _recon_jobs:
        raise HTTPException(404, "Job not found")
    vulns = _recon_jobs[job_id].get("vulnerabilities", [])
    return {"total": len(vulns), "vulnerabilities": vulns}


# ── Enrichment ────────────────────────────────────────────────────────────────

@router.post("/enrich-ip")
async def enrich_ip(req: EnrichIPRequest, current_user=Depends(get_current_user)):
    from app.services.threat_intel_service import enrich_ip as _enrich
    return await _enrich(req.ip)


@router.post("/enrich-domain")
async def enrich_domain(req: EnrichDomainRequest, current_user=Depends(get_current_user)):
    from app.services.threat_intel_service import enrich_domain as _enrich
    return await _enrich(req.domain)


# ── AI Analysis ───────────────────────────────────────────────────────────────

@router.post("/ai/analyze-vulnerability")
async def ai_analyze_vuln(req: AIAnalyzeRequest, current_user=Depends(get_current_user)):
    """Gemini AI vulnerability analysis."""
    from app.services.threat_intel_service import gemini_analyze_vulnerability
    return await gemini_analyze_vulnerability(
        cve_id=req.cve_id, title=req.title, description=req.description,
        severity=req.severity, cvss_score=req.cvss_score,
        affected_service=req.affected_service,
    )


# ── Provider status ───────────────────────────────────────────────────────────

@router.get("/providers/status")
async def providers_status(current_user=Depends(get_current_user)):
    def avail(name): return shutil.which(name) is not None or os.path.isfile(
        os.path.join(settings.pd_tools_path, name))
    
    chrome_path = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chrome")
    chrome_avail = chrome_path is not None
    
    pd_tools = {
        t: {"available": avail(t)}
        for t in ["subfinder","dnsx","naabu","httpx","nuclei","gowitness","nmap","katana"]
    }
    ready = all(tool["available"] for tool in pd_tools.values())
    
    return {
        "ready": ready,
        "browser": {
            "chromium": {
                "available": chrome_avail,
                "path": chrome_path or "/usr/bin/chromium"
            }
        },
        "ai_providers": {
            "gemini": {"configured": bool(settings.gemini_api_key), "primary": True},
            "claude": {"configured": bool(settings.claude_api_key)},
            "openai": {"configured": bool(settings.openai_api_key)},
        },
        "threat_intelligence": {
            "virustotal": {"configured": bool(settings.virustotal_api_key), "primary": True},
            "shodan":     {"configured": bool(settings.shodan_api_key),     "primary": True},
            "abuseipdb":  {"configured": bool(settings.abuseipdb_api_key)},
            "greynoise":  {"configured": bool(settings.greynoise_api_key)},
        },
        "projectdiscovery_tools": pd_tools,
    }
