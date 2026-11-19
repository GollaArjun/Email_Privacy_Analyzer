from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from fastapi import APIRouter, Depends
from app.config import settings as app_settings
from app.security.auth import get_optional_current_user
from app.database.mongo import get_settings_col
from app.schemas.analysis import UserSettingsModel, UserSettingsUpdate, SuspiciousURL
from app.services.phishing_detector import (
    PhishingDetectorService, KNOWN_SHORTENERS, SUSPICIOUS_TLDS, POPULAR_BRANDS
)
from app.services.tracking_detector import KNOWN_TRACKING_SERVICES

router = APIRouter(prefix="/api", tags=["Settings and Threat Intelligence"])

class InspectUrlRequest(BaseModel):
    url: str

@router.get("/settings", response_model=UserSettingsModel)
def get_user_settings(current_user: Optional[dict] = Depends(get_optional_current_user)):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    col = get_settings_col()
    doc = col.find_one({"user_id": user_id})
    if not doc:
        return UserSettingsModel(
            user_id=user_id,
            ai_enabled=app_settings.AI_ENABLED_DEFAULT,
            ollama_model=app_settings.OLLAMA_MODEL,
            retention_period_days=30,
            mask_pii_in_reports=True
        )

    return UserSettingsModel(
        user_id=user_id,
        ai_enabled=doc.get("ai_enabled", True),
        ollama_model=doc.get("ollama_model", app_settings.OLLAMA_MODEL),
        retention_period_days=doc.get("retention_period_days", 30),
        mask_pii_in_reports=doc.get("mask_pii_in_reports", True),
        notification_preferences=doc.get("notification_preferences", {
            "high_risk_alerts": True,
            "weekly_digest": False,
            "phishing_alerts": True
        })
    )

@router.put("/settings", response_model=UserSettingsModel)
def update_user_settings(
    update: UserSettingsUpdate,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    col = get_settings_col()

    fields_to_update = {k: v for k, v in update.model_dump().items() if v is not None}
    fields_to_update["user_id"] = user_id

    col.update_one({"user_id": user_id}, {"$set": fields_to_update}, upsert=True)
    return get_user_settings(current_user)

@router.get("/threat-intel")
def get_threat_intelligence():
    """Directory of known phishing indicators, tracking networks, and suspicious TLD patterns."""
    return {
        "tracking_services_count": len(KNOWN_TRACKING_SERVICES),
        "tracking_services": [
            {"domain": k, "service_name": v, "category": "Email Marketing / Telemetry Beacon"}
            for k, v in KNOWN_TRACKING_SERVICES.items()
        ],
        "suspicious_tlds_count": len(SUSPICIOUS_TLDS),
        "suspicious_tlds": sorted(list(SUSPICIOUS_TLDS)),
        "popular_url_shorteners": sorted(list(KNOWN_SHORTENERS)),
        "targeted_brands": [b.capitalize() for b in POPULAR_BRANDS],
        "threat_advisories": [
            {
                "id": "ADV-2026-001",
                "title": "Surge in Punycode Homograph Attacks in Banking Phishing",
                "severity": "HIGH",
                "date": "Nov 2026",
                "summary": "Adversaries are registering Cyrillic and Greek homoglyphs mimicking PayPal and Microsoft authentication portals."
            },
            {
                "id": "ADV-2026-002",
                "title": "Zero-Pixel Read Receipts Used for Recipient IP Profiling",
                "severity": "MEDIUM",
                "date": "Nov 2026",
                "summary": "Third-party outreach platforms embed transparent 1x1 GIF trackers to harvest client device location and email open times."
            },
            {
                "id": "ADV-2026-003",
                "title": "Double-Extension Payloads Bypass Email Gateway Filters",
                "severity": "CRITICAL",
                "date": "Nov 2026",
                "summary": "Attackers disguise executable and script payloads with deceptive naming patterns like .pdf.exe or .docx.vbs."
            }
        ]
    }

@router.post("/threat-intel/inspect-url")
def inspect_url_standalone(req: InspectUrlRequest):
    """Inspect any URL on demand for phishing, shorteners, punycode, or open-redirect vulnerabilities."""
    urls, findings = PhishingDetectorService.analyze_urls([req.url])
    result = urls[0] if urls else SuspiciousURL(
        url=req.url,
        domain="",
        risk_factors=["Could not parse destination domain"]
    )
    return {
        "url_analysis": result,
        "findings": findings
    }
