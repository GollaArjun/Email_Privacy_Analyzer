import pytest
from app.services.email_parser import EmailParserService

SAMPLE_MIME = """From: "Sender Name" <sender@example.com>
To: recipient1@target.com, recipient2@target.com
Subject: Test Email Subject
Date: Sun, 15 Nov 2026 12:00:00 +0000
Message-ID: <unique-12345@example.com>
Reply-To: replies@example.com
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Visit our website at <a href="https://example.com/login">Login Portal</a></p>
<img src="https://example.com/pixel.gif" width="1" height="1" />
</body>
</html>
"""

def test_mime_header_parsing():
    parsed = EmailParserService.parse_raw_email(SAMPLE_MIME)
    assert "Sender Name" in parsed.sender
    assert len(parsed.recipients) == 2
    assert parsed.subject == "Test Email Subject"
    assert parsed.reply_to == "replies@example.com"
    assert parsed.message_id == "<unique-12345@example.com>"

def test_url_and_image_extraction():
    parsed = EmailParserService.parse_raw_email(SAMPLE_MIME)
    assert any("example.com/login" in u for u in parsed.extracted_urls)
    assert len(parsed.extracted_images) >= 1
    assert parsed.extracted_images[0]["width"] == "1"
    assert parsed.extracted_images[0]["height"] == "1"
