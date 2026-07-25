"""
API endpoints for AI-powered vulnerability analysis.
Supports Claude, OpenAI, Gemini, and other AI providers.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.ai_vulnerability_service import AIVulnerabilityAnalyzer, VulnerabilityExplainer
from app.repositories.scan_repo import ScanRepository
from app.models import Vulnerability
from app.exceptions import ExternalServiceError, ValidationError
from app.dependencies import get_current_user
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai", tags=["ai-analysis"])


@router.post("/analyze/vulnerability/{vulnerability_id}")
async def analyze_vulnerability(
    vulnerability_id: str,
    provider: str = Query("claude", regex="^(claude|openai|gemini|all)$"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze a vulnerability using AI.
    
    Providers:
    - claude: Anthropic Claude (recommended)
    - openai: OpenAI GPT-4
    - gemini: Google Gemini
    - all: Get analysis from all available providers
    """
    try:
        # Get vulnerability
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        ai_analyzer = AIVulnerabilityAnalyzer(db)

        if provider == "all":
            result = await ai_analyzer.explain_vulnerability_multi_ai(vuln)
        elif provider == "claude":
            result = await ai_analyzer.analyze_vulnerability_claude(vuln)
        elif provider == "openai":
            result = await ai_analyzer.analyze_vulnerability_openai(vuln)
        elif provider == "gemini":
            result = await ai_analyzer.analyze_vulnerability_gemini(vuln)
        else:
            raise ValidationError("Invalid provider")

        return result
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error analyzing vulnerability: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to analyze vulnerability")


@router.post("/remediate/{vulnerability_id}")
async def get_remediation_steps(
    vulnerability_id: str,
    ai_provider: str = Query("claude", regex="^(claude|openai)$"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get remediation steps for a vulnerability using AI.
    """
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        ai_analyzer = AIVulnerabilityAnalyzer(db)

        if ai_provider == "claude":
            steps = await ai_analyzer.get_remediation_steps_claude(vuln)
        else:
            raise ValidationError("Provider not yet implemented for remediation")

        return {
            "vulnerability_id": vulnerability_id,
            "cve_id": vuln.cve_id,
            "title": vuln.title,
            "remediation_steps": steps,
            "ai_provider": ai_provider
        }
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error getting remediation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get remediation steps")


@router.post("/prioritize")
async def prioritize_vulnerabilities(
    asset_id: str,
    severity_filter: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    ai_provider: str = Query("claude"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Prioritize vulnerabilities for an asset using AI.
    AI analyzes CVSS score, severity, exploitability, and business impact.
    """
    try:
        # Get vulnerabilities for asset
        query = db.query(Vulnerability)
        
        if severity_filter:
            query = query.filter(Vulnerability.severity == severity_filter)
        
        vulnerabilities = query.limit(limit).all()
        
        if not vulnerabilities:
            return {
                "message": "No vulnerabilities found",
                "asset_id": asset_id
            }

        ai_analyzer = AIVulnerabilityAnalyzer(db)

        if ai_provider == "claude":
            result = await ai_analyzer.prioritize_vulnerabilities_claude(vulnerabilities)
        else:
            raise ValidationError("Provider not yet implemented for prioritization")

        return result
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error prioritizing vulnerabilities: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to prioritize vulnerabilities")


@router.post("/report/executive/{asset_id}")
async def generate_executive_report(
    asset_id: str,
    ai_provider: str = Query("claude"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generate an executive security report using AI.
    Includes summary, key findings, risk assessment, and recommendations.
    """
    try:
        # Get vulnerabilities for asset
        vulnerabilities = db.query(Vulnerability).limit(50).all()
        
        if not vulnerabilities:
            return {
                "message": "No vulnerabilities found for report",
                "asset_id": asset_id
            }

        # Count by severity
        critical = len([v for v in vulnerabilities if v.severity == "Critical"])
        high = len([v for v in vulnerabilities if v.severity == "High"])
        medium = len([v for v in vulnerabilities if v.severity == "Medium"])

        ai_analyzer = AIVulnerabilityAnalyzer(db)

        if ai_provider == "claude":
            report = await ai_analyzer.generate_executive_report_claude(
                asset_id, vulnerabilities, critical, high, medium
            )
        else:
            raise ValidationError("Provider not yet implemented for reports")

        return {
            "asset_id": asset_id,
            "report": report,
            "vulnerability_summary": {
                "total": len(vulnerabilities),
                "critical": critical,
                "high": high,
                "medium": medium
            },
            "ai_provider": ai_provider
        }
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/explain/{vulnerability_id}")
async def explain_vulnerability(
    vulnerability_id: str,
    audience: str = Query("technical", regex="^(technical|manager|developer)$"),
    ai_provider: str = Query("claude"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a tailored explanation of a vulnerability for different audiences.
    
    Audiences:
    - technical: Technical details for security teams
    - manager: Business impact for management
    - developer: Fix strategy for developers
    """
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        ai_analyzer = AIVulnerabilityAnalyzer(db)

        if audience == "technical":
            explanation = await ai_analyzer.analyze_vulnerability_claude(vuln)
        elif audience == "manager":
            # Business-focused explanation
            prompt = f"""
            Explain this vulnerability in business terms (avoid technical jargon):
            
            CVE: {vuln.cve_id}
            Title: {vuln.title}
            Severity: {vuln.severity}
            
            Focus on business impact, financial risk, and compliance implications.
            """
            explanation = {"analysis": prompt, "audience": "manager"}
        elif audience == "developer":
            explanation = await ai_analyzer.analyze_vulnerability_claude(vuln)
        else:
            raise ValidationError("Invalid audience")

        return {
            "vulnerability_id": vulnerability_id,
            "cve_id": vuln.cve_id,
            "title": vuln.title,
            "audience": audience,
            "explanation": explanation,
            "ai_provider": ai_provider
        }
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error explaining vulnerability: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to explain vulnerability")


@router.get("/providers")
async def get_available_providers(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of available AI providers and their status."""
    from app.config import settings
    
    providers = {
        "claude": {
            "name": "Anthropic Claude",
            "available": bool(settings.claude_api_key),
            "models": ["claude-3-opus", "claude-3-sonnet"]
        },
        "openai": {
            "name": "OpenAI GPT-4",
            "available": bool(settings.openai_api_key),
            "models": ["gpt-4", "gpt-4-turbo"]
        },
        "gemini": {
            "name": "Google Gemini",
            "available": bool(settings.gemini_api_key),
            "models": ["gemini-pro"]
        },
        "cohere": {
            "name": "Cohere",
            "available": bool(settings.cohere_api_key),
            "models": ["command", "command-nightly"]
        }
    }

    return {
        "providers": providers,
        "recommended": "claude" if settings.claude_api_key else "openai"
    }


@router.post("/batch-analyze")
async def batch_analyze_vulnerabilities(
    vulnerability_ids: List[str],
    ai_provider: str = Query("claude"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze multiple vulnerabilities in batch using AI.
    """
    try:
        vulns = db.query(Vulnerability).filter(
            Vulnerability.id.in_(vulnerability_ids)
        ).all()

        if not vulns:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")

        ai_analyzer = AIVulnerabilityAnalyzer(db)
        results = []

        for vuln in vulns:
            try:
                if ai_provider == "claude":
                    analysis = await ai_analyzer.analyze_vulnerability_claude(vuln)
                    results.append(analysis)
            except Exception as e:
                logger.warning(f"Failed to analyze {vuln.id}: {str(e)}")
                results.append({
                    "vulnerability_id": vuln.id,
                    "error": str(e)
                })

        return {
            "total_vulnerabilities": len(vulns),
            "analyzed": len([r for r in results if "error" not in r]),
            "failed": len([r for r in results if "error" in r]),
            "results": results,
            "ai_provider": ai_provider
        }
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=f"AI service error: {e.message}")
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to analyze vulnerabilities")
