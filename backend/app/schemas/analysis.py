from typing import List, Dict, Any, Optional
from pydantic import BaseModel, EmailStr, Field

# ----------------- AUTH SCHEMAS -----------------
class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class UserProfileResponse(BaseModel):
    user_id: str
    name: str
    email: str
    created_at: str
    stats: Optional[Dict[str, Any]] = None

class UserUpdateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6, max_length=128)

# ----------------- SETTINGS SCHEMAS -----------------
class UserSettingsModel(BaseModel):
    user_id: str
    ai_enabled: bool = True
    ollama_model: str = "llama3"
    retention_period_days: int = 30  # 0 = infinite
    mask_pii_in_reports: bool = True
    notification_preferences: Dict[str, bool] = {
        "high_risk_alerts": True,
        "weekly_digest": False,
        "phishing_alerts": True
    }

class UserSettingsUpdate(BaseModel):
    ai_enabled: Optional[bool] = None
    ollama_model: Optional[str] = None
    retention_period_days: Optional[int] = None
    mask_pii_in_reports: Optional[bool] = None
    notification_preferences: Optional[Dict[str, bool]] = None

# ----------------- FINDINGS SCHEMAS -----------------
class PIIFinding(BaseModel):
    entity_type: str
    text_masked: str
    confidence: float
    severity: str  # low, medium, high, critical
    description: str

class SuspiciousURL(BaseModel):
    url: str
    domain: str
    is_shortener: bool = False
    is_punycode: bool = False
    is_ip_host: bool = False
    has_redirect: bool = False
    suspicious_tld: bool = False
    risk_factors: List[str] = []

class PhishingFinding(BaseModel):
    category: str  # url, mismatch, urgency, impersonation
    title: str
    description: str
    severity: str
    evidence_masked: str
    indicators: List[str] = []

class TrackingFinding(BaseModel):
    tracking_type: str  # 1x1_pixel, web_beacon, remote_image, esp_tracker
    tracker_name: Optional[str] = None
    url: str
    is_zero_dimension: bool = False
    severity: str
    description: str

class HeaderSecurityFinding(BaseModel):
    header_name: str
    value_summary: str
    status: str  # PASS, FAIL, SOFTFAIL, NONE, SUSPICIOUS, UNVERIFIED
    severity: str
    explanation: str

class AttachmentFinding(BaseModel):
    filename: str
    file_size_bytes: int
    content_type: str
    detected_type: str
    extension: str
    is_executable: bool = False
    is_macro: bool = False
    is_double_extension: bool = False
    is_mime_mismatch: bool = False
    is_suspicious: bool = False
    md5_hash: str
    sha256_hash: str
    risk_level: str
    recommendation: str

# ----------------- REPORT & METADATA SCHEMAS -----------------
class EmailMetadata(BaseModel):
    sender: str
    reply_to: Optional[str] = None
    recipients: List[str] = []
    cc: List[str] = []
    bcc: List[str] = []
    subject: str
    date: str
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    body_text_length: int = 0
    body_preview: str = ""
    has_html: bool = False
    has_attachments: bool = False
    attachments_count: int = 0

class RiskAssessment(BaseModel):
    overall_score: int  # 0 to 100
    risk_category: str  # Low, Moderate, High, Very High, Critical
    category_color: str  # hex or tailwind class
    score_breakdown: Dict[str, int]
    score_explanation: str
    findings_count: Dict[str, int]
    recommended_actions: List[str]
    is_heuristic: bool = True
    disclaimer: str = "Score is an application-specific heuristic calculated by EPA threat rules and not an official certification."

class AIAssessment(BaseModel):
    ai_engine_status: str  # "ollama_active" or "heuristic_ai_active"
    model_name: str
    threat_verdict: str
    contextual_analysis: str
    key_observations: List[str]
    remediation_guidance: List[str]

class ThreatIntelMatch(BaseModel):
    indicator_value: str
    indicator_type: str  # URL, DOMAIN, IP, HASH
    matched_source: str  # e.g., "OpenPhish Community Feed", "CISA KEV"
    source_url: Optional[str] = None
    threat_type: str     # Phishing, Malware, Exploited CVE
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str      # Confirmed, Corroborated, Reported, Unverified
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    explanation: str
    reputation_verdict: str

class ThreatIntelReport(BaseModel):
    indicators_scanned_count: int = 0
    matches_count: int = 0
    status: str = "NO_MATCH_FOUND"  # "MATCHES_FOUND" or "NO_MATCH_FOUND"
    verdict_summary: str = "No match found in checked sources"
    matches: List[ThreatIntelMatch] = []
    sources_checked: List[str] = []
    timestamp: str = ""

class AnalysisFindings(BaseModel):
    pii_findings: List[PIIFinding] = []
    phishing_findings: List[PhishingFinding] = []
    suspicious_urls: List[SuspiciousURL] = []
    tracking_findings: List[TrackingFinding] = []
    header_findings: List[HeaderSecurityFinding] = []
    attachment_findings: List[AttachmentFinding] = []
    threat_intel: Optional[ThreatIntelReport] = None

class AnalysisReport(BaseModel):
    report_id: str
    user_id: str
    created_at: str
    email_metadata: EmailMetadata
    findings: AnalysisFindings
    risk_assessment: RiskAssessment
    ai_assessment: AIAssessment

# ----------------- DASHBOARD SCHEMAS -----------------
class DashboardStatsResponse(BaseModel):
    total_emails_analyzed: int
    high_risk_emails: int
    critical_findings_count: int
    pii_leaks_count: int
    phishing_attempts_count: int
    tracking_pixels_count: int
    risk_distribution: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]
    security_alerts: List[Dict[str, Any]]

# ----------------- GMAIL SCHEMAS -----------------
class GmailMessageSummary(BaseModel):
    id: str
    thread_id: str
    sender: str
    subject: str
    date: str
    snippet: str

class GmailAnalyzeRequest(BaseModel):
    message_ids: List[str]

class RawEmailAnalyzeRequest(BaseModel):
    raw_email: str
    email_filename: Optional[str] = "pasted_email.eml"
