import pytest
from app.services.scoring_engine import ScoringEngineService
from app.schemas.analysis import (
    PIIFinding, PhishingFinding, TrackingFinding,
    HeaderSecurityFinding, AttachmentFinding, SuspiciousURL
)

def test_clean_email_low_score():
    risk = ScoringEngineService.calculate_risk(
        pii_findings=[],
        phishing_findings=[],
        suspicious_urls=[],
        tracking_findings=[],
        header_findings=[HeaderSecurityFinding(
            header_name="SPF", value_summary="PASS", status="PASS", severity="low", explanation="Valid"
        )],
        attachment_findings=[]
    )
    assert risk.overall_score < 20
    assert risk.risk_category == "Low"

def test_critical_phishing_and_credential_score():
    risk = ScoringEngineService.calculate_risk(
        pii_findings=[PIIFinding(
            entity_type="EXPOSED_PASSWORD", text_masked="••••••••", confidence=0.99, severity="critical", description="Password leaked"
        )],
        phishing_findings=[PhishingFinding(
            category="mismatch", title="Domain Mismatch", description="Mismatch", severity="critical", evidence_masked="abc != def", indicators=[]
        )],
        suspicious_urls=[SuspiciousURL(
            url="http://192.168.1.1/login", domain="192.168.1.1", is_ip_host=True
        )],
        tracking_findings=[],
        header_findings=[HeaderSecurityFinding(
            header_name="SPF", value_summary="FAIL", status="FAIL", severity="high", explanation="SPF Fail"
        )],
        attachment_findings=[AttachmentFinding(
            filename="trojan.exe", file_size_bytes=1000, content_type="app/exe", detected_type=".exe", extension="exe",
            is_executable=True, md5_hash="1", sha256_hash="2", risk_level="CRITICAL", recommendation="Quarantine"
        )]
    )
    assert risk.overall_score >= 80
    assert risk.risk_category == "Critical"
    assert "CRITICAL" in risk.recommended_actions[0]
