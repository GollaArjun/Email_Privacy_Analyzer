import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from app.config import settings
from app.security.auth import get_optional_current_user
from app.database.mongo import get_reports_col, get_settings_col
from app.services.email_parser import EmailParserService
from app.services.pii_detector import PIIDetectorService
from app.services.phishing_detector import PhishingDetectorService
from app.services.tracking_detector import TrackingDetectorService
from app.services.header_analyzer import HeaderAnalyzerService
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.threat_intel_correlator import ThreatIntelCorrelatorService
from app.services.scoring_engine import ScoringEngineService
from app.services.ai_engine import AIEngineService
from app.schemas.analysis import (
    AnalysisReport, AnalysisFindings, EmailMetadata, RawEmailAnalyzeRequest
)
from app.utils.sample_emails import SAMPLE_EMAILS

logger = logging.getLogger("epa.routes.analyze")
router = APIRouter(prefix="/api/analyze", tags=["Email Analysis Engine"])

pii_service = PIIDetectorService()

async def _process_email_content(content: bytes | str, user_id: str) -> AnalysisReport:
    """Core analysis orchestrator combining all deterministic and AI modules."""
    # 1. Parse MIME email structure
    parsed = EmailParserService.parse_raw_email(content)
    metadata_dict = parsed.to_metadata_dict()
    email_metadata = EmailMetadata(**metadata_dict)

    # 2. PII Detection (Presidio + Custom Recognizers)
    combined_body = f"{parsed.subject}\n{parsed.text_content}"
    pii_findings = pii_service.analyze_text(combined_body)

    # 3. Phishing Detection (URLs, shorteners, punycode, mismatches, urgency)
    suspicious_urls, phishing_findings = PhishingDetectorService.evaluate(parsed)

    # 4. Tracking & Web Beacon Detection
    tracking_findings = TrackingDetectorService.detect_trackers(parsed)

    # 5. Header Security Analysis (SPF, DKIM, DMARC, Received hops)
    header_findings = HeaderAnalyzerService.analyze_headers(parsed)

    # 6. Attachment Threat Analysis
    attachment_findings = AttachmentAnalyzerService.analyze_attachments(parsed)

    # 7. Live Threat Intelligence Feed Correlation (OpenPhish, CISA KEV, Cyber Incidents)
    extracted_urls = list(set(parsed.extracted_urls + [u.url for u in suspicious_urls]))
    threat_intel_report = ThreatIntelCorrelatorService.correlate(
        urls=extracted_urls,
        sender_email=parsed.sender,
        attachment_findings=attachment_findings,
        suspicious_urls=suspicious_urls
    )

    # 8. Privacy & Security Risk Scoring Engine (0-100 explainable score)
    risk_assessment = ScoringEngineService.calculate_risk(
        pii_findings=pii_findings,
        phishing_findings=phishing_findings,
        suspicious_urls=suspicious_urls,
        tracking_findings=tracking_findings,
        header_findings=header_findings,
        attachment_findings=attachment_findings,
        threat_intel_matches=threat_intel_report.matches
    )

    # 9. User Settings check (AI enabled toggle)
    settings_col = get_settings_col()
    user_settings = settings_col.find_one({"user_id": user_id}) or {}
    ai_enabled = user_settings.get("ai_enabled", settings.AI_ENABLED_DEFAULT)
    ollama_model = user_settings.get("ollama_model", settings.OLLAMA_MODEL)

    findings_container = AnalysisFindings(
        pii_findings=pii_findings,
        phishing_findings=phishing_findings,
        suspicious_urls=suspicious_urls,
        tracking_findings=tracking_findings,
        header_findings=header_findings,
        attachment_findings=attachment_findings,
        threat_intel=threat_intel_report
    )

    # 10. Hybrid AI Assessment (Ollama LLM or Heuristic Cyber Analyst)
    ai_assessment = await AIEngineService.analyze(
        metadata=email_metadata,
        findings=findings_container,
        risk=risk_assessment,
        ai_enabled=ai_enabled,
        model_name=ollama_model
    )

    # 11. Generate Report Document
    report_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    report = AnalysisReport(
        report_id=report_id,
        user_id=user_id,
        created_at=created_at,
        email_metadata=email_metadata,
        findings=findings_container,
        risk_assessment=risk_assessment,
        ai_assessment=ai_assessment
    )

    # 12. Persist in MongoDB (Never save raw body or plaintext credentials)
    try:
        reports_col = get_reports_col()
        report_dict = report.model_dump()
        reports_col.insert_one(report_dict)
    except Exception as e:
        logger.warning(f"Error persisting report to database: {e}")

    return report

@router.post("/eml", response_model=AnalysisReport)
async def analyze_eml_file(
    file: UploadFile = File(...),
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Analyze uploaded .eml file."""
    if not file.filename.lower().endswith(('.eml', '.msg', '.txt')):
        raise HTTPException(status_code=400, detail="Only .eml, .msg, or .txt email files are supported.")

    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_BYTES // (1024*1024)}MB.")

    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    return await _process_email_content(content, user_id)

@router.post("/raw", response_model=AnalysisReport)
async def analyze_raw_email(
    req: RawEmailAnalyzeRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Analyze raw RFC822 email text or body content pasted into the analyzer."""
    if not req.raw_email or not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")

    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    return await _process_email_content(req.raw_email, user_id)

@router.get("/samples")
def get_sample_emails():
    """Retrieve pre-packaged synthetic test emails for instant testing."""
    return [
        {
            "id": key,
            "title": data["title"],
            "description": data["description"],
            "content": data["content"]
        }
        for key, data in SAMPLE_EMAILS.items()
    ]
