import pytest
from app.services.tracking_detector import TrackingDetectorService
from app.services.email_parser import ParsedEmail

def test_invisible_pixel_detection():
    email = ParsedEmail()
    email.extracted_images = [
        {"src": "https://sendgrid.net/wf/open?upn=123", "width": "1", "height": "1", "style": "", "alt": ""},
        {"src": "https://company.com/banner.png", "width": "600", "height": "200", "style": "", "alt": "banner"}
    ]
    findings = TrackingDetectorService.detect_trackers(email)
    pixel_findings = [f for f in findings if f.is_zero_dimension]
    assert len(pixel_findings) >= 1
    assert "sendgrid" in pixel_findings[0].url.lower()

def test_known_esp_telemetry():
    email = ParsedEmail()
    email.extracted_urls = ["https://list-manage.com/track/click?u=abc&id=123"]
    findings = TrackingDetectorService.detect_trackers(email)
    assert len(findings) >= 1
    assert "Mailchimp" in (findings[0].tracker_name or "")
