"""
Threat Intelligence Service
Gemini API, VirusTotal, Shodan — connected and required.
If key is empty the call is skipped and result shows 'key_not_configured'.
"""

import httpx
import json
from typing import Optional, Dict, Any, List
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

_VT_BASE   = "https://www.virustotal.com/api/v3"
_SHODAN    = "https://api.shodan.io"
_GREYNOISE = "https://api.greynoise.io/v3/community"
_ABUSEIPDB = "https://api.abuseipdb.com/api/v2"


# ─── VirusTotal ──────────────────────────────────────────────────────────────

async def vt_check_ip(ip: str) -> Dict[str, Any]:
    if not settings.virustotal_api_key:
        return {"provider": "virustotal", "status": "key_not_configured", "ip": ip}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
    if r.status_code != 200:
        return {"provider": "virustotal", "status": "error", "code": r.status_code, "ip": ip}
    d = r.json().get("data", {}).get("attributes", {})
    stats = d.get("last_analysis_stats", {})
    return {
        "provider":        "virustotal",
        "ip":              ip,
        "malicious":       stats.get("malicious", 0),
        "suspicious":      stats.get("suspicious", 0),
        "harmless":        stats.get("harmless", 0),
        "reputation":      d.get("reputation", 0),
        "country":         d.get("country", ""),
        "asn":             d.get("asn", ""),
        "as_owner":        d.get("as_owner", ""),
        "is_malicious":    stats.get("malicious", 0) > 0,
    }


async def vt_check_domain(domain: str) -> Dict[str, Any]:
    if not settings.virustotal_api_key:
        return {"provider": "virustotal", "status": "key_not_configured", "domain": domain}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{_VT_BASE}/domains/{domain}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
    if r.status_code != 200:
        return {"provider": "virustotal", "status": "error", "code": r.status_code}
    d = r.json().get("data", {}).get("attributes", {})
    stats = d.get("last_analysis_stats", {})
    return {
        "provider":     "virustotal",
        "domain":       domain,
        "malicious":    stats.get("malicious", 0),
        "suspicious":   stats.get("suspicious", 0),
        "categories":   d.get("categories", {}),
        "reputation":   d.get("reputation", 0),
        "is_malicious": stats.get("malicious", 0) > 0,
    }


async def vt_check_hash(file_hash: str) -> Dict[str, Any]:
    if not settings.virustotal_api_key:
        return {"provider": "virustotal", "status": "key_not_configured"}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{_VT_BASE}/files/{file_hash}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
    if r.status_code != 200:
        return {"provider": "virustotal", "status": "error", "code": r.status_code}
    d = r.json().get("data", {}).get("attributes", {})
    stats = d.get("last_analysis_stats", {})
    return {
        "provider":    "virustotal",
        "hash":        file_hash,
        "malicious":   stats.get("malicious", 0),
        "name":        d.get("meaningful_name", ""),
        "type":        d.get("type_description", ""),
        "is_malicious": stats.get("malicious", 0) > 0,
    }


# ─── Shodan ──────────────────────────────────────────────────────────────────

async def shodan_lookup_ip(ip: str) -> Dict[str, Any]:
    if not settings.shodan_api_key:
        return {"provider": "shodan", "status": "key_not_configured", "ip": ip}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(
            f"{_SHODAN}/shodan/host/{ip}",
            params={"key": settings.shodan_api_key},
        )
    if r.status_code != 200:
        return {"provider": "shodan", "status": "error", "code": r.status_code, "ip": ip}
    d = r.json()
    return {
        "provider":   "shodan",
        "ip":         ip,
        "org":        d.get("org", ""),
        "isp":        d.get("isp", ""),
        "country":    d.get("country_name", ""),
        "city":       d.get("city", ""),
        "os":         d.get("os", ""),
        "hostnames":  d.get("hostnames", []),
        "domains":    d.get("domains", []),
        "open_ports": d.get("ports", []),
        "tags":       d.get("tags", []),
        "vulns":      list(d.get("vulns", {}).keys()),
        "services": [
            {
                "port":    s.get("port"),
                "product": s.get("product", ""),
                "version": s.get("version", ""),
                "banner":  s.get("data", "")[:200],
            }
            for s in d.get("data", [])
        ],
    }


async def shodan_search(query: str, limit: int = 10) -> Dict[str, Any]:
    if not settings.shodan_api_key:
        return {"provider": "shodan", "status": "key_not_configured"}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(
            f"{_SHODAN}/shodan/host/search",
            params={"key": settings.shodan_api_key, "query": query, "limit": limit},
        )
    if r.status_code != 200:
        return {"provider": "shodan", "status": "error", "code": r.status_code}
    d = r.json()
    return {
        "provider": "shodan",
        "total":    d.get("total", 0),
        "matches": [
            {
                "ip":      m.get("ip_str", ""),
                "port":    m.get("port"),
                "org":     m.get("org", ""),
                "country": m.get("location", {}).get("country_name", ""),
                "product": m.get("product", ""),
            }
            for m in d.get("matches", [])
        ],
    }


# ─── AbuseIPDB (direct REST, no broken pip package) ──────────────────────────

async def abuseipdb_check_ip(ip: str) -> Dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {"provider": "abuseipdb", "status": "key_not_configured", "ip": ip}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{_ABUSEIPDB}/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        )
    if r.status_code != 200:
        return {"provider": "abuseipdb", "status": "error", "code": r.status_code}
    d = r.json().get("data", {})
    return {
        "provider":         "abuseipdb",
        "ip":               ip,
        "abuse_score":      d.get("abuseConfidenceScore", 0),
        "country":          d.get("countryCode", ""),
        "usage_type":       d.get("usageType", ""),
        "isp":              d.get("isp", ""),
        "domain":           d.get("domain", ""),
        "total_reports":    d.get("totalReports", 0),
        "is_malicious":     d.get("abuseConfidenceScore", 0) >= 50,
    }


# ─── GreyNoise ───────────────────────────────────────────────────────────────

async def greynoise_check_ip(ip: str) -> Dict[str, Any]:
    if not settings.greynoise_api_key:
        return {"provider": "greynoise", "status": "key_not_configured", "ip": ip}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{_GREYNOISE}/{ip}",
            headers={"key": settings.greynoise_api_key},
        )
    if r.status_code == 404:
        return {"provider": "greynoise", "ip": ip, "noise": False, "riot": False}
    if r.status_code != 200:
        return {"provider": "greynoise", "status": "error", "code": r.status_code}
    d = r.json()
    return {
        "provider":    "greynoise",
        "ip":          ip,
        "noise":       d.get("noise", False),
        "riot":        d.get("riot", False),
        "classification": d.get("classification", ""),
        "name":        d.get("name", ""),
        "link":        d.get("link", ""),
        "last_seen":   d.get("last_seen", ""),
        "message":     d.get("message", ""),
    }


# ─── Gemini AI analysis ───────────────────────────────────────────────────────

async def gemini_analyze_vulnerability(
    cve_id: str,
    title: str,
    description: str,
    severity: str,
    cvss_score: Optional[float] = None,
    affected_service: Optional[str] = None,
) -> Dict[str, Any]:
    """Use Gemini to analyze a vulnerability and suggest remediation."""
    if not settings.gemini_api_key:
        return {"provider": "gemini", "status": "key_not_configured"}
    try:
        from app.services.ai_pentest.gemini_core import ai_report
        prompt = f"""You are a senior cybersecurity expert. Analyze this vulnerability and provide:
1. Business Risk Assessment (2-3 sentences, non-technical)
2. Technical Root Cause
3. Exploitation Likelihood (Low/Medium/High) with reasoning
4. Step-by-step Remediation (5-7 numbered steps)
5. Verification steps to confirm the fix

Vulnerability Details:
- CVE ID: {cve_id or "N/A"}
- Title: {title}
- Severity: {severity}
- CVSS Score: {cvss_score or "N/A"}
- Description: {description or "N/A"}
{f"- Affected Service: {affected_service}" if affected_service else ""}

Be specific and actionable. Focus on practical remediation steps."""
        text = await ai_report(prompt)
        return {
            "provider": "gemini", "model": "gemini-1.5-pro",
            "cve_id": cve_id, "severity": severity,
            "analysis": text, "status": "success",
        }
    except Exception as e:
        logger.error(f"Gemini analyze error: {e}")
        return {"provider": "gemini", "status": "error", "error": str(e)}


async def gemini_prioritize_vulns(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Gemini: rank vulnerabilities by priority."""
    if not settings.gemini_api_key:
        return {"provider": "gemini", "status": "key_not_configured"}
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-pro")

        vuln_text = "\n".join([
            f"{i+1}. {v.get('cve_id','N/A')} | {v.get('title','')} | {v.get('severity','')} | CVSS {v.get('cvss_score','?')}"
            for i, v in enumerate(vulns[:20])
        ])

        prompt = f"""Rank these vulnerabilities by remediation priority (1=highest).
Consider: CVSS score, exploitability, business impact, patch availability.

Vulnerabilities:
{vuln_text}

Return:
1. Ranked numbered list with brief justification per item
2. Top 3 critical actions to take immediately
3. Estimated effort (hours) for each fix"""

        response = model.generate_content(prompt)
        return {
            "provider":       "gemini",
            "prioritization": response.text,
            "total_analyzed": len(vulns),
            "status":         "success",
        }
    except Exception as e:
        logger.error(f"Gemini prioritization error: {e}")
        return {"provider": "gemini", "status": "error", "error": str(e)}


async def gemini_generate_report(
    asset_name: str,
    subdomains_count: int,
    unique_ips: List[str],
    open_ports: Dict[str, List[int]],
    vulnerabilities: List[Dict[str, Any]],
    screenshots_count: int,
) -> Dict[str, Any]:
    """Gemini: generate executive security report."""
    if not settings.gemini_api_key:
        return {"provider": "gemini", "status": "key_not_configured"}
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-pro")

        crit = len([v for v in vulnerabilities if v.get("severity") == "Critical"])
        high = len([v for v in vulnerabilities if v.get("severity") == "High"])
        med  = len([v for v in vulnerabilities if v.get("severity") == "Medium"])

        prompt = f"""Write a professional executive security report for:

Asset: {asset_name}
Scan Summary:
- Subdomains discovered: {subdomains_count}
- Unique IPs: {len(unique_ips)} ({', '.join(unique_ips[:5])}{'...' if len(unique_ips) > 5 else ''})
- Hosts with open ports: {len(open_ports)}
- Vulnerabilities: {len(vulnerabilities)} total ({crit} Critical, {high} High, {med} Medium)
- Screenshots captured: {screenshots_count}

Format the report with:
1. Executive Summary (3-4 sentences for non-technical audience)
2. Key Findings (bullet points)
3. Risk Rating (Critical/High/Medium/Low) with justification
4. Immediate Actions Required (top 3)
5. Recommended Remediation Timeline (30/60/90 day plan)
6. Next Steps"""

        response = model.generate_content(prompt)
        return {
            "provider": "gemini",
            "report":   response.text,
            "status":   "success",
        }
    except Exception as e:
        logger.error(f"Gemini report error: {e}")
        return {"provider": "gemini", "status": "error", "error": str(e)}


# ─── Unified enrichment ───────────────────────────────────────────────────────

async def enrich_ip(ip: str) -> Dict[str, Any]:
    """Run all TI providers against an IP concurrently."""
    import asyncio
    vt, shodan, abuse, gn = await asyncio.gather(
        vt_check_ip(ip),
        shodan_lookup_ip(ip),
        abuseipdb_check_ip(ip),
        greynoise_check_ip(ip),
        return_exceptions=True,
    )
    return {
        "ip":         ip,
        "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
        "shodan":     shodan if not isinstance(shodan, Exception) else {"error": str(shodan)},
        "abuseipdb":  abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
        "greynoise":  gn if not isinstance(gn, Exception) else {"error": str(gn)},
        "is_malicious": any([
            vt.get("is_malicious") if isinstance(vt, dict) else False,
            abuse.get("is_malicious") if isinstance(abuse, dict) else False,
        ]),
    }


async def enrich_domain(domain: str) -> Dict[str, Any]:
    """Run all TI providers against a domain."""
    import asyncio
    vt, shodan = await asyncio.gather(
        vt_check_domain(domain),
        shodan_search(f"hostname:{domain}", limit=5),
        return_exceptions=True,
    )
    return {
        "domain":     domain,
        "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
        "shodan":     shodan if not isinstance(shodan, Exception) else {"error": str(shodan)},
    }
