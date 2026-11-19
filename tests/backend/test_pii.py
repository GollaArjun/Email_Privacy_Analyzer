import pytest
from app.services.pii_detector import PIIDetectorService, mask_text

@pytest.fixture(scope="module")
def pii_detector():
    return PIIDetectorService()

def test_aadhaar_detection(pii_detector):
    text = "Please verify my Aadhaar: 4582 9102 3847 for processing."
    findings = pii_detector.analyze_text(text)
    aadhaar_findings = [f for f in findings if "AADHAAR" in f.entity_type]
    assert len(aadhaar_findings) >= 1
    # Check masking
    assert "4582 9102 3847" not in aadhaar_findings[0].text_masked
    assert "XXXX" in aadhaar_findings[0].text_masked

def test_pan_card_detection(pii_detector):
    text = "Tax PAN number submitted: ABCDE1234F."
    findings = pii_detector.analyze_text(text)
    pan_findings = [f for f in findings if "PAN" in f.entity_type]
    assert len(pan_findings) >= 1
    assert "ABCDE1234F" not in pan_findings[0].text_masked

def test_credential_leak_detection(pii_detector):
    text = "Your temporary login credentials are password = SuperSecret2026! please change it."
    findings = pii_detector.analyze_text(text)
    pw_findings = [f for f in findings if "PASSWORD" in f.entity_type]
    assert len(pw_findings) >= 1
    assert "SuperSecret2026!" not in pw_findings[0].text_masked
    assert "REDACTED" in pw_findings[0].text_masked

def test_aws_key_detection(pii_detector):
    text = "Staging access key: AKIAIOSFODNN7EXAMPLE for developer access."
    findings = pii_detector.analyze_text(text)
    key_findings = [f for f in findings if "AWS" in f.entity_type]
    assert len(key_findings) >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in key_findings[0].text_masked
