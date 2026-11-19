import pytest
from app.services.phishing_detector import PhishingDetectorService
from app.services.email_parser import ParsedEmail

def test_suspicious_url_detection():
    urls = [
        "http://bit.ly/secure-login-392",
        "http://192.168.1.1/admin",
        "https://portal.account-security.xyz/verify?redirect=http://google.com"
    ]
    suspicious, findings = PhishingDetectorService.analyze_urls(urls)
    assert len(suspicious) >= 3
    assert any(s.is_shortener for s in suspicious)
    assert any(s.is_ip_host for s in suspicious)
    assert any(s.suspicious_tld for s in suspicious)

def test_sender_mismatch():
    email = ParsedEmail()
    email.sender = "support@bank-security.com"
    email.reply_to = "attacker@mail-collector.top"
    
    mismatch_findings = PhishingDetectorService.analyze_sender_mismatch(email)
    assert len(mismatch_findings) >= 1
    assert "Mismatch" in mismatch_findings[0].title

def test_urgency_detection():
    text = "Immediate action required: Your account is suspended. Confirm identity within 24 hours."
    findings = PhishingDetectorService.analyze_manipulative_language(text, "URGENT")
    assert len(findings) >= 1
    assert findings[0].category == "urgency"
