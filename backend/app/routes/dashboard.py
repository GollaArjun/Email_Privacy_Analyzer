from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends
from app.security.auth import get_optional_current_user
from app.database.mongo import get_reports_col
from app.schemas.analysis import DashboardStatsResponse

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Statistics"])

@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(current_user: Optional[dict] = Depends(get_optional_current_user)):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    reports_col = get_reports_col()

    # Match user's reports (or demo reports)
    reports = list(reports_col.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1))
    
    # If anonymous user has no reports yet, check all reports or provide realistic starter stats
    if not reports:
        reports = list(reports_col.find({}, {"_id": 0}).sort("created_at", -1).limit(10))

    total = len(reports)
    high_risk = 0
    critical_findings = 0
    pii_leaks = 0
    phishing_count = 0
    tracking_pixels = 0

    risk_counts = {
        "Low": 0,
        "Moderate": 0,
        "High": 0,
        "Very High": 0,
        "Critical": 0
    }

    recent_activity: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []

    for r in reports:
        risk_info = r.get("risk_assessment", {})
        cat = risk_info.get("risk_category", "Low")
        score = risk_info.get("overall_score", 0)

        if cat in risk_counts:
            risk_counts[cat] += 1

        if cat in ["High", "Very High", "Critical"]:
            high_risk += 1

        findings = r.get("findings", {})
        pii_list = findings.get("pii_findings", [])
        phish_list = findings.get("phishing_findings", [])
        track_list = findings.get("tracking_findings", [])
        att_list = findings.get("attachment_findings", [])

        pii_leaks += len(pii_list)
        phishing_count += len(phish_list)
        tracking_pixels += len([t for t in track_list if t.get("is_zero_dimension")])
        critical_findings += len([p for p in pii_list if p.get("severity") == "critical"])
        critical_findings += len([p for p in phish_list if p.get("severity") == "critical"])
        critical_findings += len([a for a in att_list if a.get("risk_level") == "CRITICAL"])

        meta = r.get("email_metadata", {})
        recent_activity.append({
            "report_id": r.get("report_id"),
            "sender": meta.get("sender", "Unknown"),
            "subject": meta.get("subject", "(No Subject)"),
            "score": score,
            "risk_category": cat,
            "category_color": risk_info.get("category_color", "#10B981"),
            "date": r.get("created_at", "")
        })

        if cat in ["Very High", "Critical"] and len(alerts) < 5:
            alerts.append({
                "type": "CRITICAL_THREAT",
                "title": f"Threat detected in '{meta.get('subject', 'Email')[:30]}...'",
                "sender": meta.get("sender", "Unknown"),
                "date": r.get("created_at", ""),
                "score": score,
                "reasons": risk_info.get("recommended_actions", ["Immediate quarantine advised"])[:2]
            })

    # Prepare chart risk distribution
    risk_distribution = [
        {"name": "Low (0-19)", "count": risk_counts["Low"], "color": "#10B981"},
        {"name": "Moderate (20-39)", "count": risk_counts["Moderate"], "color": "#3B82F6"},
        {"name": "High (40-59)", "count": risk_counts["High"], "color": "#EAB308"},
        {"name": "Very High (60-79)", "count": risk_counts["Very High"], "color": "#F97316"},
        {"name": "Critical (80-100)", "count": risk_counts["Critical"], "color": "#EF4444"}
    ]

    return DashboardStatsResponse(
        total_emails_analyzed=total,
        high_risk_emails=high_risk,
        critical_findings_count=critical_findings,
        pii_leaks_count=pii_leaks,
        phishing_attempts_count=phishing_count,
        tracking_pixels_count=tracking_pixels,
        risk_distribution=risk_distribution,
        recent_activity=recent_activity[:8],
        security_alerts=alerts
    )
