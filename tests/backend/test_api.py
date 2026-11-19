import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "database" in data

def test_threat_intel_endpoint():
    res = client.get("/api/threat-intel")
    assert res.status_code == 200
    data = res.json()
    assert "tracking_services" in data
    assert "threat_advisories" in data

def test_samples_endpoint():
    res = client.get("/api/analyze/samples")
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) >= 4

def test_analyze_raw_email_endpoint():
    sample_eml = """From: "Bank Operations" <security@secure-verify.xyz>
To: victim@example.com
Subject: URGENT: Account Suspended Immediately
Date: Sun, 15 Nov 2026 12:00:00 +0000

Immediate action required. Verify your credentials: http://192.168.1.1/login
Your temporary password: SecretPassword123!
"""
    res = client.post("/api/analyze/raw", json={"raw_email": sample_eml})
    assert res.status_code == 200
    data = res.json()
    assert "report_id" in data
    assert "risk_assessment" in data
    assert data["risk_assessment"]["overall_score"] > 40
    # Verify masking
    assert "SecretPassword123!" not in str(data["findings"])

def test_auth_registration_and_login():
    email = f"test_{pytest.__version__}@example.com"
    reg_res = client.post("/api/auth/register", json={
        "name": "Security Tester",
        "email": email,
        "password": "SecurePassword@123"
    })
    # Either registered or existing
    assert reg_res.status_code in [200, 400]
    
    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "SecurePassword@123"
    })
    if login_res.status_code == 200:
        token = login_res.json()["access_token"]
        assert token is not None
        me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.json()["email"] == email

def test_analyze_eml_file_upload():
    import os
    import io
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_samples", "normal_email.eml")
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            content = f.read()
    else:
        content = b"From: sender@domain.com\nTo: user@domain.com\nSubject: Test\nDate: Mon, 16 Nov 2026 00:00:00 +0000\n\nContent"

    res = client.post("/api/analyze/eml", files={"file": ("test.eml", io.BytesIO(content), "message/rfc822")})
    assert res.status_code == 200
    data = res.json()
    assert "report_id" in data
    assert "email_metadata" in data
    assert "findings" in data
    assert "risk_assessment" in data
    assert data["risk_assessment"]["overall_score"] < 40

def test_analyze_eml_phishing_upload():
    import os
    import io
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_samples", "phishing_email.eml")
    assert os.path.exists(sample_path), "phishing_email.eml must exist"
    with open(sample_path, "rb") as f:
        content = f.read()

    res = client.post("/api/analyze/eml", files={"file": ("phishing_email.eml", io.BytesIO(content), "message/rfc822")})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_assessment"]["overall_score"] >= 60
    assert len(data["findings"]["phishing_findings"]) > 0

def test_analyze_eml_invalid_extension():
    import io
    res = client.post("/api/analyze/eml", files={"file": ("malicious.exe", io.BytesIO(b"binary"), "application/octet-stream")})
    assert res.status_code == 400
    assert "Only .eml, .msg, or .txt" in res.json()["detail"]
