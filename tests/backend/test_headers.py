import pytest
from app.services.header_analyzer import HeaderAnalyzerService
from app.services.email_parser import ParsedEmail

def test_spf_dkim_dmarc_pass():
    email = ParsedEmail()
    email.headers = {
        "authentication-results": ["mx.google.com; spf=pass; dkim=pass; dmarc=pass"],
        "received": ["from mail.example.com by mx.google.com"],
        "message-id": ["<id-123@example.com>"]
    }
    findings = HeaderAnalyzerService.analyze_headers(email)
    spf = next(f for f in findings if "SPF" in f.header_name)
    dkim = next(f for f in findings if "DKIM" in f.header_name)
    dmarc = next(f for f in findings if "DMARC" in f.header_name)
    assert spf.status == "PASS"
    assert dkim.status == "PASS"
    assert dmarc.status == "PASS"

def test_spf_fail():
    email = ParsedEmail()
    email.headers = {
        "authentication-results": ["mx.google.com; spf=fail; dkim=fail; dmarc=fail"],
        "received": [],
    }
    findings = HeaderAnalyzerService.analyze_headers(email)
    spf = next(f for f in findings if "SPF" in f.header_name)
    assert spf.status == "FAIL"
    assert spf.severity == "high"
