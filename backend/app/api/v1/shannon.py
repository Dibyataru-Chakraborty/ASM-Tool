"""
Shannon AI Pentester mock/simulation API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from app.dependencies import get_current_user
import uuid
import asyncio
from datetime import datetime

router = APIRouter(prefix="/shannon", tags=["shannon"])

# In-memory database to store scan states
shannon_scans: Dict[str, Dict[str, Any]] = {}

class StartScanRequest(BaseModel):
    target_url: str

class StartScanResponse(BaseModel):
    scan_id: str

# Background task to simulate the 5-phase AI Pentest
async def run_shannon_scan_simulation(scan_id: str, target_url: str):
    phases = [
        ("phase2", "Crawling target website and discovering entry points..."),
        ("phase1", "Identifying active technologies, services, and versions..."),
        ("phase2b", "Mapping attack surface, forms, headers, and API routes..."),
        ("phase3", "Spinning up 5 specialized AI vulnerability detection agents..."),
        ("phase4", "Simulating safe payload verification and exploitation attempts..."),
        ("phase5", "Synthesizing agent logs, PoCs, and generating executive report...")
    ]
    
    for phase_id, message in phases:
        if scan_id not in shannon_scans:
            return
        shannon_scans[scan_id]["phase"] = phase_id
        shannon_scans[scan_id]["message"] = message
        # Wait 3 seconds per phase to simulate execution
        await asyncio.sleep(3)
        
    # Finalize scan state
    if scan_id not in shannon_scans:
        return
        
    finished_time = datetime.utcnow().isoformat() + "Z"
    
    findings = [
        {
            "index": 1,
            "title": "SQL Injection in Registration Endpoint",
            "severity": "critical",
            "cvss_score": 9.8,
            "vuln_class": "sqli",
            "target_url": f"{target_url}/api/v1/auth/register",
            "parameter": "email",
            "method": "POST",
            "payload": "test' OR 1=1--",
            "evidence": "SQL syntax error or unexpected database dump contents",
            "description": "Input passed to the email field in the registration endpoint is concatenated directly into SQL queries. An attacker can exploit this to dump database content or bypass verification.",
            "poc": "Submit 'test\\' OR 1=1--' as the email parameter to bypass authentication checks.",
            "curl_command": f"curl -X POST -H 'Content-Type: application/json' -d '{{\"email\":\"test\\' OR 1=1--\"}}' {target_url}/api/v1/auth/register"
        },
        {
            "index": 2,
            "title": "Path Traversal in Static File Serving Router",
            "severity": "high",
            "cvss_score": 8.5,
            "vuln_class": "lfi",
            "target_url": f"{target_url}/static/file",
            "parameter": "path",
            "method": "GET",
            "payload": "../../../../etc/passwd",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
            "description": "Path traversal allows an unauthenticated user to read arbitrary local files on the server hosting the application by passing relative file paths.",
            "poc": f"Navigate to {target_url}/static/file?path=../../../../etc/passwd to read local server config files.",
            "curl_command": f"curl '{target_url}/static/file?path=../../../../etc/passwd'"
        }
    ]
    
    shannon_scans[scan_id].update({
        "status": "completed",
        "phase": "done",
        "message": "Scan completed successfully.",
        "report": {
            "findings_count": len(findings),
            "summary": f"We performed an automated 5-phase AI-driven pentest on {target_url}. Two high-impact vulnerabilities were discovered and verified with working PoCs: one critical SQL Injection and one high-severity Path Traversal. Exploit verification was fully completed by the AI agents.",
            "findings": findings,
            "markdown": f"""# Shannon AI Pentest Report for {target_url}
Generated: {finished_time}
Policy: No Exploit = No Finding

## Executive Summary
Shannon AI Pentester completed the execution pipeline against `{target_url}`. In accordance with Shannon's strict no-false-positive policy, only vulnerabilities with a successfully executed and verified Proof of Concept (PoC) are reported.

Total Findings: 2
- Critical: 1
- High: 1

---

## Findings Details

### 1. SQL Injection in Registration Endpoint (CVSS 9.8 - Critical)
- **Target URL**: `{target_url}/api/v1/auth/register`
- **Parameter**: `email` (POST)
- **Payload**: `test' OR 1=1--`

**Description**:
The application fails to sanitize inputs before inserting them into PostgreSQL database query strings. An attacker can exploit this SQL injection vulnerability to manipulate SQL commands and retrieve all table contents.

**Remediation**:
Use parameterized queries or ORM models instead of building raw SQL string concatenations.

---

### 2. Path Traversal in Static File Serving Router (CVSS 8.5 - High)
- **Target URL**: `{target_url}/static/file`
- **Parameter**: `path` (GET)
- **Payload**: `../../../../etc/passwd`

**Description**:
The file retrieval system does not validate that requested paths lie inside the intended static assets folder, enabling directory traversal and disclosure of arbitrary operating system files.

**Remediation**:
Sanitize path components or verify that the resolved path starts with the base static directory path.
""",
            "attack_surface": {
                "framework": "React / Next.js",
                "language": "JavaScript / TypeScript",
                "auth_mechanism": "JWT Bearer Tokens / OAuth2",
                "target_url": target_url,
                "technologies": ["Next.js", "React", "TailwindCSS", "Node.js", "Nginx", "PostgreSQL", "Prisma"],
                "endpoints": [
                    {"method": "GET", "url": "/api/v1/auth/me", "notes": "Active Session Check"},
                    {"method": "POST", "url": "/api/v1/auth/login", "notes": "JWT Token Issue"},
                    {"method": "POST", "url": "/api/v1/auth/register", "notes": "User Creation"},
                    {"method": "GET", "url": "/api/v1/dashboard/full", "notes": "Metrics and Stats"},
                    {"method": "POST", "url": "/api/v1/shannon/scan", "notes": "AI Pentester Trigger (High-Value)"}
                ]
            },
            "started_at": shannon_scans[scan_id]["started_at"],
            "finished_at": finished_time
        }
    })

@router.post("/scan", response_model=StartScanResponse)
async def start_scan(
    request: StartScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """Start Shannon AI pentest scan."""
    scan_id = str(uuid.uuid4())
    started_time = datetime.utcnow().isoformat() + "Z"
    
    shannon_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "phase": "phase2",
        "message": "Initializing scan and starting crawl...",
        "target_url": request.target_url,
        "started_at": started_time
    }
    
    background_tasks.add_task(run_shannon_scan_simulation, scan_id, request.target_url)
    
    return {"scan_id": scan_id}

@router.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    current_user = Depends(get_current_user)
):
    """Get status of Shannon scan."""
    if scan_id not in shannon_scans:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        
    return shannon_scans[scan_id]
