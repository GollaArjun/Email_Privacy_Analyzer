import pytest
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.email_parser import ParsedEmail

def test_executable_attachment():
    email = ParsedEmail()
    email.attachments = [{
        "filename": "payroll_update.exe",
        "file_size_bytes": 1024 * 50,
        "content_type": "application/octet-stream",
        "extension": "exe",
        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }]
    findings = AttachmentAnalyzerService.analyze_attachments(email)
    assert len(findings) == 1
    assert findings[0].is_executable is True
    assert findings[0].risk_level == "CRITICAL"

def test_double_extension_attachment():
    email = ParsedEmail()
    email.attachments = [{
        "filename": "Invoice_Nov2026.pdf.vbs",
        "file_size_bytes": 1024,
        "content_type": "text/plain",
        "extension": "vbs",
        "md5_hash": "abc",
        "sha256_hash": "def"
    }]
    findings = AttachmentAnalyzerService.analyze_attachments(email)
    assert len(findings) == 1
    assert findings[0].is_double_extension is True
    assert findings[0].risk_level == "CRITICAL"

def test_mime_mismatch_attachment():
    # Innocent extension .pdf but executable MIME application/x-dosexec
    email = ParsedEmail()
    email.attachments = [{
        "filename": "Contract_Agreement.pdf",
        "file_size_bytes": 1024 * 10,
        "content_type": "application/x-dosexec",
        "extension": "pdf",
        "md5_hash": "abc123",
        "sha256_hash": "def456"
    }]
    findings = AttachmentAnalyzerService.analyze_attachments(email)
    assert len(findings) == 1
    assert findings[0].is_mime_mismatch is True
    assert findings[0].risk_level == "CRITICAL"
    assert "MIME MISMATCH" in findings[0].recommendation

def test_oversized_attachment():
    email = ParsedEmail()
    email.attachments = [{
        "filename": "LargeArchive.zip",
        "file_size_bytes": 20 * 1024 * 1024,
        "content_type": "application/zip",
        "extension": "zip",
        "md5_hash": "abc123",
        "sha256_hash": "def456"
    }]
    findings = AttachmentAnalyzerService.analyze_attachments(email)
    assert len(findings) == 1
    assert findings[0].risk_level == "MEDIUM"
    assert "Oversized attachment" in findings[0].recommendation
