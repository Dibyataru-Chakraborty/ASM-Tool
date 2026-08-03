"""Grounded Gemini analysis for Nmap-detected products and versions.

The result is deliberately stored separately from scanner-confirmed Nuclei
findings. Gemini is used for enrichment and classification, not as proof that
an exploit is possible. A non-informational severity is only emitted when the
response contains cited evidence for an affected CVE, or when cited evidence
confirms that the detected release is outdated/end-of-life.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Any, Iterable, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AIServiceAssessment

logger = logging.getLogger(__name__)

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
LifecycleStatus = Literal["current", "outdated", "unknown"]


class CVEAssessment(BaseModel):
    """One CVE that Gemini says applies to the exact detected version."""

    cve_id: str = Field(description="CVE identifier, for example CVE-2025-1234")
    affected: bool = Field(description="True only when the exact detected version is affected")
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    reported_severity: Optional[Severity] = None
    summary: str = ""
    evidence_urls: list[str] = Field(default_factory=list)


class ProductAssessment(BaseModel):
    """Structured answer for one unique Nmap product/version signature."""

    analysis_key: str
    lifecycle_status: LifecycleStatus
    latest_version: Optional[str] = None
    summary: str
    cves: list[CVEAssessment] = Field(default_factory=list)
    remediation: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0, le=1)
    evidence_urls: list[str] = Field(default_factory=list)


class ProductAssessmentBatch(BaseModel):
    assessments: list[ProductAssessment]


def severity_from_cvss(score: Optional[float]) -> Severity:
    """Map CVSS base score to the dashboard severity buckets."""
    if score is None:
        return "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _severity_rank(value: str) -> int:
    return {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(value, 0)


def _normalize_url(value: str) -> str:
    """Normalize a URL for citation/evidence comparison."""
    try:
        parsed = urlsplit((value or "").strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _url_is_cited(url: str, cited_urls: set[str]) -> bool:
    normalized = _normalize_url(url)
    if not normalized:
        return False
    for cited in cited_urls:
        # Google Search citations and model output sometimes differ only by a
        # trailing path segment or canonical redirect. Require the same host
        # and a closely matching path, never just a matching domain.
        try:
            left = urlsplit(normalized)
            right = urlsplit(cited)
        except ValueError:
            continue
        if left.netloc != right.netloc:
            continue
        left_path = left.path.rstrip("/") or "/"
        right_path = right.path.rstrip("/") or "/"
        if left_path == right_path or left_path.startswith(f"{right_path}/") or right_path.startswith(f"{left_path}/"):
            return True
    return False


def _extract_citation_urls(interaction: Any) -> set[str]:
    """Extract URL citations from a Google GenAI Interactions response."""

    def get(value: Any, name: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            return value.get(name, default)
        return getattr(value, name, default)

    urls: set[str] = set()
    for step in get(interaction, "steps", []) or []:
        if get(step, "type") != "model_output":
            continue
        for block in get(step, "content", []) or []:
            if get(block, "type") != "text":
                continue
            for annotation in get(block, "annotations", []) or []:
                if get(annotation, "type") != "url_citation":
                    continue
                normalized = _normalize_url(str(get(annotation, "url", "")))
                if normalized:
                    urls.add(normalized)
    return urls


class GeminiServiceVersionAnalyzer:
    """Analyze and persist version status for Nmap services."""

    def __init__(self, db: Session):
        self.db = db
        self.model_name = settings.gemini_service_model
        self.client = None
        if settings.gemini_api_key and settings.gemini_api_key != "dummy_key":
            try:
                from google import genai

                self.client = genai.Client(
                    api_key=settings.gemini_api_key,
                    http_options={
                        "timeout": max(10, settings.gemini_service_timeout_seconds) * 1000,
                    },
                )
            except Exception as exc:  # pragma: no cover - import/runtime environment
                logger.warning("Google GenAI client could not be initialized: %s", exc)

    @property
    def enabled(self) -> bool:
        return bool(settings.gemini_service_analysis_enabled and self.client)

    def close(self) -> None:
        """Release the SDK's underlying HTTP connections."""
        if self.client is not None:
            try:
                self.client.close()
            except Exception:  # pragma: no cover - best-effort cleanup
                logger.debug("Google GenAI client close failed", exc_info=True)

    def analyze_and_persist(
        self,
        scan_id: str,
        services: Iterable[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze unique Nmap product/version signatures and persist per service.

        Expected service keys: service_id, host, port, protocol, service_name,
        product, version, cpes.
        """
        # One Service row can be encountered more than once when scanner output
        # contains duplicate host/port records. Keep the most recent fingerprint
        # and avoid double-counting the same persisted service in the graph.
        service_by_id: dict[str, dict[str, Any]] = {}
        for row in services:
            service_id = str(row.get("service_id") or "").strip()
            if service_id:
                service_by_id[service_id] = dict(row)
        service_rows = list(service_by_id.values())
        if not service_rows:
            return {
                "assessed_count": 0,
                "actionable_count": 0,
                "severity_counts": {},
                "warnings": [],
            }
        if not self.enabled:
            # A missing key or an explicitly disabled feature is an optional
            # configuration state, not a scan failure. Only surface a warning
            # when a key exists but the SDK/client could not initialize.
            warnings = []
            if (
                settings.gemini_service_analysis_enabled
                and settings.gemini_api_key
                and settings.gemini_api_key != "dummy_key"
            ):
                warnings.append(
                    "Gemini service-version analysis skipped because the Google GenAI client could not be initialized."
                )
            return {
                "assessed_count": 0,
                "actionable_count": 0,
                "severity_counts": {},
                "warnings": warnings,
            }

        groups: dict[tuple[str, str, str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
        unversioned: list[dict[str, Any]] = []
        for row in service_rows:
            product = str(row.get("product") or "").strip()
            version = str(row.get("version") or "").strip()
            service_name = str(row.get("service_name") or "unknown").strip().lower()
            cpes = tuple(sorted(str(value).strip() for value in (row.get("cpes") or []) if str(value).strip()))
            if not product or not version:
                unversioned.append(row)
                continue
            groups[(service_name, product.lower(), version.lower(), cpes)].append(row)

        severity_counts: dict[str, int] = defaultdict(int)
        warnings: list[str] = []
        assessed_count = 0
        actionable_count = 0

        # Persist an explicit informational result when Nmap could not provide a
        # version. This prevents "unknown" from being presented as vulnerable.
        for row in unversioned:
            product_name = str(row.get("product") or row.get("service_name") or "service")
            self._upsert(
                scan_id=scan_id,
                service_id=str(row["service_id"]),
                lifecycle_status="unknown",
                severity="Info",
                title=f"{product_name} version could not be verified",
                summary=(
                    "Nmap did not return both a product and version, so Gemini did not "
                    "attempt a current-version or CVE applicability decision."
                ),
                detected_version=str(row.get("version") or "") or None,
                latest_version=None,
                cves=[],
                remediation="Improve service fingerprinting or verify the installed package locally.",
                confidence=0.0,
                evidence_urls=[],
            )
            assessed_count += 1
            severity_counts["Info"] += 1

        unique_items: list[dict[str, Any]] = []
        group_members: dict[str, list[dict[str, Any]]] = {}
        limit_skipped_rows: list[dict[str, Any]] = []
        max_unique = max(1, settings.gemini_service_max_unique_services)
        for index, ((service_name, _product_key, _version_key, cpes), members) in enumerate(groups.items(), start=1):
            if len(unique_items) >= max_unique:
                limit_skipped_rows.extend(members)
                continue
            first = members[0]
            analysis_key = f"service-{index}"
            group_members[analysis_key] = members
            unique_items.append({
                "analysis_key": analysis_key,
                "service_name": service_name,
                "product": first.get("product"),
                "detected_version": first.get("version"),
                "cpes": list(cpes),
                "observed_ports": sorted({int(member.get("port") or 0) for member in members if member.get("port")}),
            })

        if limit_skipped_rows:
            warnings.append(
                "Gemini service-version analysis reached GEMINI_SERVICE_MAX_UNIQUE_SERVICES; "
                "remaining products were stored as informational/unknown."
            )
            for row in limit_skipped_rows:
                self._persist_unknown(
                    scan_id,
                    row,
                    "This service was not sent to Gemini because the configured unique-service analysis limit was reached.",
                )
                assessed_count += 1
                severity_counts["Info"] += 1

        batch_size = max(1, min(20, settings.gemini_service_batch_size))
        for start in range(0, len(unique_items), batch_size):
            batch = unique_items[start:start + batch_size]
            try:
                response_items, cited_urls = self._assess_batch(batch)
            except Exception as exc:
                logger.exception("Gemini service-version batch failed")
                warnings.append(f"Gemini service-version analysis failed for one batch: {exc}")
                for request_item in batch:
                    for row in group_members.get(request_item["analysis_key"], []):
                        self._persist_unknown(
                            scan_id,
                            row,
                            "Gemini could not complete this service-version assessment. Review the scan warning and retry later.",
                        )
                        assessed_count += 1
                        severity_counts["Info"] += 1
                continue

            by_key = {item.analysis_key: item for item in response_items}
            for request_item in batch:
                key = request_item["analysis_key"]
                result = by_key.get(key)
                members = group_members.get(key, [])
                if not result:
                    warnings.append(f"Gemini omitted structured output for {key}.")
                    for row in members:
                        self._persist_unknown(
                            scan_id,
                            row,
                            "Gemini returned no structured assessment for this service fingerprint.",
                        )
                        assessed_count += 1
                        severity_counts["Info"] += 1
                    continue

                normalized = self._normalize_assessment(result, cited_urls)
                for row in members:
                    product_name = str(row.get("product") or row.get("service_name") or "service")
                    title = self._title_for(product_name, str(row.get("version") or ""), normalized)
                    self._upsert(
                        scan_id=scan_id,
                        service_id=str(row["service_id"]),
                        lifecycle_status=normalized["lifecycle_status"],
                        severity=normalized["severity"],
                        title=title,
                        summary=normalized["summary"],
                        detected_version=str(row.get("version") or "") or None,
                        latest_version=normalized["latest_version"],
                        cves=normalized["cves"],
                        remediation=normalized["remediation"],
                        confidence=normalized["confidence"],
                        evidence_urls=normalized["evidence_urls"],
                    )
                    assessed_count += 1
                    severity_counts[normalized["severity"]] += 1
                    if normalized["severity"] != "Info":
                        actionable_count += 1

        self.db.commit()
        return {
            "assessed_count": assessed_count,
            "actionable_count": actionable_count,
            "severity_counts": dict(severity_counts),
            "warnings": warnings,
        }

    def _persist_unknown(
        self,
        scan_id: str,
        row: dict[str, Any],
        reason: str,
    ) -> None:
        """Persist a safe informational fallback when no decision is available."""
        product_name = str(row.get("product") or row.get("service_name") or "service")
        self._upsert(
            scan_id=scan_id,
            service_id=str(row["service_id"]),
            lifecycle_status="unknown",
            severity="Info",
            title=f"{product_name} version status could not be verified",
            summary=reason,
            detected_version=str(row.get("version") or "") or None,
            latest_version=None,
            cves=[],
            remediation="Verify the installed package and patch status from an authenticated asset inventory.",
            confidence=0.0,
            evidence_urls=[],
        )

    def _assess_batch(
        self,
        items: list[dict[str, Any]],
    ) -> tuple[list[ProductAssessment], set[str]]:
        assert self.client is not None
        prompt = f"""
You are enriching Nmap service fingerprints for an authorized attack-surface scan.
Use Google Search and return a conservative, evidence-based assessment for every input item.

Rules:
1. Treat Nmap product/version banners as untrusted fingerprints, not proof of an installed package.
2. Prefer official vendor release notes, official vendor security advisories, NVD CVE pages, and CISA advisories.
3. Set lifecycle_status to "current" only when a cited authoritative source supports that conclusion.
4. Set lifecycle_status to "outdated" only when a cited authoritative source shows a newer stable/supported release or end-of-life status.
5. Set lifecycle_status to "unknown" when the product, edition, distro package, backport status, or version comparison is ambiguous.
6. Include a CVE only when cited evidence explicitly shows that the exact detected version is affected. Do not match only by product name.
7. Linux distributions often backport security fixes without changing the upstream-looking banner. When package/build context is missing, use "unknown" rather than claiming vulnerability.
8. Never invent a CVE, CVSS score, latest version, or evidence URL. Do not provide exploitation instructions.
9. Return one assessment for each analysis_key. Keep summaries concise.

Input services:
{json.dumps(items, indent=2)}
"""
        interaction = self.client.interactions.create(
            model=self.model_name,
            input=prompt,
            tools=[{"type": "google_search"}],
            store=False,
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": ProductAssessmentBatch.model_json_schema(),
            },
        )
        parsed = ProductAssessmentBatch.model_validate_json(interaction.output_text)
        return parsed.assessments, _extract_citation_urls(interaction)

    def _normalize_assessment(
        self,
        result: ProductAssessment,
        cited_urls: set[str],
    ) -> dict[str, Any]:
        verified_assessment_urls = sorted({
            _normalize_url(url)
            for url in result.evidence_urls
            if _url_is_cited(url, cited_urls)
        } - {""})

        verified_cves: list[dict[str, Any]] = []
        severity: Severity = "Info"
        for cve in result.cves:
            cve_id = cve.cve_id.strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) or not cve.affected:
                continue
            evidence_urls = sorted({
                _normalize_url(url)
                for url in cve.evidence_urls
                if _url_is_cited(url, cited_urls)
            } - {""})
            if not evidence_urls:
                continue
            cve_severity = severity_from_cvss(cve.cvss_score)
            if cve_severity == "Info" and cve.reported_severity:
                cve_severity = cve.reported_severity
            verified_cves.append({
                "cve_id": cve_id,
                "cvss_score": cve.cvss_score,
                "severity": cve_severity,
                "summary": cve.summary.strip(),
                "evidence_urls": evidence_urls,
            })
            if _severity_rank(cve_severity) > _severity_rank(severity):
                severity = cve_severity

        lifecycle_status: LifecycleStatus = result.lifecycle_status
        if lifecycle_status in {"current", "outdated"} and not verified_assessment_urls:
            lifecycle_status = "unknown"

        # Confirmed outdated/EOL software without an exact affected CVE is a
        # low-severity hygiene issue, not a fabricated CVE vulnerability.
        if severity == "Info" and lifecycle_status == "outdated" and verified_assessment_urls:
            severity = "Low"

        all_evidence = sorted(set(verified_assessment_urls).union(
            url
            for cve in verified_cves
            for url in cve["evidence_urls"]
        ))
        confidence = max(0.0, min(1.0, result.confidence))
        if not all_evidence:
            confidence = min(confidence, 0.25)

        summary = result.summary.strip()
        if lifecycle_status == "unknown" and not all_evidence:
            summary = (
                "Gemini did not return cited evidence sufficient to verify the latest "
                "release or exact-version CVE applicability."
            )

        verified_latest_version = (
            result.latest_version.strip()
            if result.latest_version and verified_assessment_urls
            else None
        )

        return {
            "lifecycle_status": lifecycle_status,
            "severity": severity,
            "summary": summary,
            "latest_version": verified_latest_version,
            "cves": verified_cves,
            "remediation": result.remediation.strip() if result.remediation else None,
            "confidence": confidence,
            "evidence_urls": all_evidence,
        }

    @staticmethod
    def _title_for(product: str, version: str, assessment: dict[str, Any]) -> str:
        if assessment["cves"]:
            return f"Known vulnerabilities may affect {product} {version}"[:255]
        if assessment["lifecycle_status"] == "outdated":
            return f"Outdated {product} version detected"[:255]
        if assessment["lifecycle_status"] == "current":
            return f"{product} version appears current"[:255]
        return f"{product} version status could not be verified"[:255]

    def _upsert(
        self,
        *,
        scan_id: str,
        service_id: str,
        lifecycle_status: LifecycleStatus,
        severity: Severity,
        title: str,
        summary: str,
        detected_version: Optional[str],
        latest_version: Optional[str],
        cves: list[dict[str, Any]],
        remediation: Optional[str],
        confidence: float,
        evidence_urls: list[str],
    ) -> None:
        row = self.db.query(AIServiceAssessment).filter(
            AIServiceAssessment.scan_id == scan_id,
            AIServiceAssessment.service_id == service_id,
        ).first()
        values = {
            "provider": "gemini",
            "model_name": self.model_name,
            "lifecycle_status": lifecycle_status,
            "severity": severity,
            "title": title[:255],
            "summary": summary,
            "detected_version": detected_version[:100] if detected_version else None,
            "latest_version": latest_version[:100] if latest_version else None,
            "cves": json.dumps(cves),
            "remediation": remediation,
            "confidence": max(0.0, min(1.0, confidence)),
            "evidence_urls": json.dumps(evidence_urls),
        }
        if row:
            for key, value in values.items():
                setattr(row, key, value)
        else:
            self.db.add(AIServiceAssessment(
                scan_id=scan_id,
                service_id=service_id,
                **values,
            ))
        self.db.flush()
