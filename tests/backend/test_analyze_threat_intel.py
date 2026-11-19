import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.database.mongo import get_indicators_col, get_incidents_col
from app.services.threat_intel_correlator import ThreatIntelCorrelatorService

client = TestClient(app)

SAMPLE_CLEAN_EMAIL = """From: colleague@trustedenterprise.org
To: user@mycompany.com
Subject: Team Sync Agenda for Thursday
Date: Thu, 19 Nov 2026 10:00:00 +0000
Message-ID: <clean-1234@trustedenterprise.org>
Content-Type: text/plain; charset=utf-8

Hi team,

Please find the agenda for our Thursday sync attached.
You can review the notes on https://internal.trustedenterprise.org/notes.

Best regards,
Colleague
"""

SAMPLE_PHISHING_EMAIL = """From: security-alert@support-verify-account.tk
To: victim@company.com
Subject: URGENT: Your Account Has Been Locked - Verify Immediately
Date: Thu, 19 Nov 2026 10:05:00 +0000
Message-ID: <phish-9876@support-verify-account.tk>
Content-Type: text/plain; charset=utf-8

Dear Customer,

Your account has been suspended due to suspicious activity.
Click the link below immediately to restore access:
http://malicious-credential-harvest.com/login.php

If you do not verify within 24 hours, your account will be permanently terminated.

Account Security Team
"""

def test_clean_email_shows_no_match_found_verdict():
    """Verify clean email returns 'No match found in checked sources' rather than claiming 'Safe'."""
    res = client.post("/api/analyze/raw", json={"raw_email": SAMPLE_CLEAN_EMAIL})
    assert res.status_code == 200
    data = res.json()

    findings = data.get("findings", {})
    ti = findings.get("threat_intel")
    assert ti is not None, "threat_intel must be present in analysis findings"
    assert ti["status"] == "NO_MATCH_FOUND"
    assert "No match found in checked sources" in ti["verdict_summary"]
    # Explicitly check that 'Safe' is not claimed as an absolute verdict
    assert ti["verdict_summary"] != "Safe"
    assert len(ti["matches"]) == 0
    assert ti["indicators_scanned_count"] >= 1
    assert "OpenPhish Community Feed" in ti["sources_checked"]


def test_threat_email_correlates_with_indexed_threat_feed():
    """Verify an email containing a known phishing indicator is flagged with feed match details."""
    indicators_col = get_indicators_col()
    test_lure_url = "http://malicious-credential-harvest.com/login.php"

    # Seed threat indicator into DB collection (as if synced from OpenPhish)
    indicators_col.update_one(
        {"indicator_value": test_lure_url},
        {
            "$set": {
                "indicator_value": test_lure_url,
                "indicator_type": "URL",
                "domain": "malicious-credential-harvest.com",
                "source": "OpenPhish Community Feed",
                "source_url": "https://openphish.com",
                "threat_type": "Phishing",
                "severity": "CRITICAL",
                "confidence": "Confirmed",
                "last_seen": "2026-11-19T00:00:00Z"
            }
        },
        upsert=True
    )

    res = client.post("/api/analyze/raw", json={"raw_email": SAMPLE_PHISHING_EMAIL})
    assert res.status_code == 200
    data = res.json()

    findings = data.get("findings", {})
    ti = findings.get("threat_intel")
    assert ti is not None
    assert ti["status"] == "MATCHES_FOUND"
    assert ti["matches_count"] >= 1

    # Check match attributes
    match_values = [m["indicator_value"] for m in ti["matches"]]
    assert test_lure_url in match_values

    target_match = next(m for m in ti["matches"] if m["indicator_value"] == test_lure_url)
    assert target_match["matched_source"] == "OpenPhish Community Feed"
    assert target_match["severity"] == "CRITICAL"
    assert target_match["confidence"] == "Confirmed"
    assert "credential-theft" in target_match["explanation"].lower() or "phishing" in target_match["explanation"].lower()

    # Risk score assessment incorporation
    risk = data.get("risk_assessment", {})
    assert risk["score_breakdown"]["threat_intelligence"] > 0
    assert any("THREAT INTELLIGENCE MATCH" in act for act in risk["recommended_actions"])


def test_correlator_handles_empty_inputs_safely():
    """Ensure ThreatIntelCorrelatorService handles empty lists and invalid inputs gracefully without errors."""
    report = ThreatIntelCorrelatorService.correlate(
        urls=[],
        sender_email="",
        attachment_findings=[],
        suspicious_urls=[]
    )
    assert report.indicators_scanned_count == 0
    assert report.matches_count == 0
    assert report.status == "NO_MATCH_FOUND"
    assert "No match found in checked sources" in report.verdict_summary
