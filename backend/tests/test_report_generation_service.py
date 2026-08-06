import io
import unittest
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.report_generation_service import (
    attack_complexity_from_vector,
    build_docx_report,
    build_pdf_report,
    build_scan_report_payload,
)


class ReportGenerationServiceTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.scan = SimpleNamespace(
            id="scan-123",
            reference_id="SCN-20260804-TEST1234567890",
            status="completed",
            scan_type="recon_full",
            started_at=now,
            completed_at=now,
            error_message="nuclei timed out after 3600 seconds",
            target_domain="example.test",
            target_ip=None,
            discovered_count=5,
        )
        self.asset = SimpleNamespace(
            name="Example external perimeter",
            target="example.test",
            asset_type="domain",
        )
        self.findings = [
            SimpleNamespace(
                id="finding-1",
                is_false_positive=False,
                severity="High",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                title="SQL Injection in search parameter",
                description="The search parameter matched a SQL injection template.",
                cve_id="CVE-2026-0001",
                host="app.example.test",
                port=443,
                matched_at="https://app.example.test/search?q=test",
                source="nuclei",
            ),
            SimpleNamespace(
                id="finding-2",
                is_false_positive=False,
                severity="Info",
                cvss_score=None,
                cvss_vector=None,
                title="Technology detected",
                description="Apache was detected.",
                cve_id=None,
                host="app.example.test",
                port=443,
                matched_at="https://app.example.test",
                source="scanner",
            ),
        ]

    def test_payload_is_scan_scoped_and_excludes_info_from_details(self):
        report = build_scan_report_payload(self.scan, self.asset, self.findings)

        self.assertEqual(report["severity"]["counts"]["high"], 1)
        self.assertEqual(report["severity"]["counts"]["info"], 1)
        self.assertEqual(report["severity"]["percentages"]["high"], 50.0)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["attack_complexity"], "High")
        self.assertEqual(report["findings"][0]["cwe"], "CWE-89")
        self.assertLessEqual(report["maturity"]["score"], 85)

    def test_attack_complexity_does_not_guess_when_vector_is_missing(self):
        self.assertEqual(
            attack_complexity_from_vector(None),
            "Not provided by scanner",
        )

    def test_word_and_pdf_exports_are_valid_container_formats(self):
        report = build_scan_report_payload(self.scan, self.asset, self.findings)
        docx_bytes = build_docx_report(report)
        pdf_bytes = build_pdf_report(report)

        self.assertTrue(docx_bytes.startswith(b"PK"))
        with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
            self.assertIn("word/document.xml", archive.namelist())
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 1000)


if __name__ == "__main__":
    unittest.main()
