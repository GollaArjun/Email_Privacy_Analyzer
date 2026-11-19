from typing import List, Dict, Any, Tuple, Optional
from app.schemas.analysis import (
    RiskAssessment, PIIFinding, PhishingFinding,
    TrackingFinding, HeaderSecurityFinding, AttachmentFinding, SuspiciousURL,
    ThreatIntelMatch
)

class ScoringEngineService:
    @staticmethod
    def calculate_risk(
        pii_findings: List[PIIFinding],
        phishing_findings: List[PhishingFinding],
        suspicious_urls: List[SuspiciousURL],
        tracking_findings: List[TrackingFinding],
        header_findings: List[HeaderSecurityFinding],
        attachment_findings: List[AttachmentFinding],
        threat_intel_matches: Optional[List[ThreatIntelMatch]] = None
    ) -> RiskAssessment:
        """Calculate an explainable, capped 0-100 privacy and security risk score."""

        score_breakdown: Dict[str, int] = {
            "credentials_exposure": 0,
            "pii_leakage": 0,
            "phishing_indicators": 0,
            "tracking_telemetry": 0,
            "attachment_threats": 0,
            "header_vulnerabilities": 0,
            "threat_intelligence": 0
        }

        recommended_actions: List[str] = []

        # 1. Credentials Exposure & PII Leakage (Cap: 45 pts total)
        has_credentials = False
        pii_points = 0
        for p in pii_findings:
            etype = p.entity_type.upper()
            if any(k in etype for k in ["PASSWORD", "KEY", "TOKEN", "SECRET"]):
                has_credentials = True
                score_breakdown["credentials_exposure"] += 25
            elif any(k in etype for k in ["AADHAAR", "PAN", "CARD"]):
                pii_points += 15
            elif "PHONE" in etype or "IP" in etype:
                pii_points += 5
            else:
                pii_points += 3

        score_breakdown["credentials_exposure"] = min(score_breakdown["credentials_exposure"], 40)
        score_breakdown["pii_leakage"] = min(pii_points, 20)

        if has_credentials:
            recommended_actions.append("CRITICAL: Immediately revoke and rotate any passwords, API keys, or access tokens exposed in this message.")
        if score_breakdown["pii_leakage"] > 0:
            recommended_actions.append("PII Alert: Government identifiers or contact numbers were detected in plaintext. Avoid forwarding this email outside trusted channels.")

        # 2. Phishing Indicators & Suspicious URLs (Cap: 45 pts)
        phish_points = 0
        has_critical_url = False
        for url in suspicious_urls:
            if url.is_ip_host or url.is_punycode or len(url.risk_factors) >= 2:
                phish_points += 20
                has_critical_url = True
            elif url.is_shortener:
                phish_points += 10
            else:
                phish_points += 5

        for pf in phishing_findings:
            if pf.severity == "critical":
                phish_points += 25
            elif pf.severity == "high":
                phish_points += 15
            elif pf.severity == "medium":
                phish_points += 8

        score_breakdown["phishing_indicators"] = min(phish_points, 45)

        if has_critical_url or any(pf.category == "mismatch" for pf in phishing_findings):
            recommended_actions.append("PHISHING WARNING: Do not click any links or provide credentials. The sender domain or destination links exhibit deceptive traits.")
        if any(pf.category == "urgency" for pf in phishing_findings):
            recommended_actions.append("Verify out-of-band: High-urgency financial or security lures detected. Contact the alleged sender through a known trusted phone number.")

        # 3. Attachment Threats (Cap: 40 pts)
        att_points = 0
        has_dangerous_att = False
        for att in attachment_findings:
            if att.risk_level == "CRITICAL" or att.is_executable or att.is_double_extension:
                att_points += 35
                has_dangerous_att = True
            elif att.risk_level == "HIGH" or att.is_macro:
                att_points += 20
                has_dangerous_att = True
            elif att.risk_level == "MEDIUM":
                att_points += 8

        score_breakdown["attachment_threats"] = min(att_points, 40)
        if has_dangerous_att:
            recommended_actions.append("MALICIOUS ATTACHMENT: Quarantine and delete the attached files without opening. Executable or macro-enabled content detected.")

        # 4. Header Vulnerabilities (SPF, DKIM, DMARC) (Cap: 25 pts)
        hdr_points = 0
        for h in header_findings:
            if h.status == "FAIL":
                hdr_points += 12
            elif h.status in ["SOFTFAIL", "NONE", "SUSPICIOUS"]:
                hdr_points += 5

        score_breakdown["header_vulnerabilities"] = min(hdr_points, 25)
        if score_breakdown["header_vulnerabilities"] >= 15:
            recommended_actions.append("Header Alert: Domain authentication (SPF/DKIM/DMARC) failed or is missing, indicating possible sender address spoofing.")

        # 5. Tracking & Telemetry (Cap: 15 pts)
        track_points = 0
        has_zero_pixel = False
        for t in tracking_findings:
            if t.is_zero_dimension:
                track_points += 8
                has_zero_pixel = True
            else:
                track_points += 3

        score_breakdown["tracking_telemetry"] = min(track_points, 15)
        if has_zero_pixel:
            recommended_actions.append("Privacy Tracking: Block remote images in your email client to prevent the sender from logging your IP address and open timestamp.")

        # 6. Live Threat Intelligence Feed Matches (Cap: 40 pts)
        if threat_intel_matches:
            ti_points = 0
            for tm in threat_intel_matches:
                if tm.severity == "CRITICAL":
                    ti_points += 35
                elif tm.severity == "HIGH":
                    ti_points += 20
                else:
                    ti_points += 10
            score_breakdown["threat_intelligence"] = min(ti_points, 40)
            recommended_actions.insert(0, f"THREAT INTELLIGENCE MATCH: An indicator in this message matched active threat intelligence ({threat_intel_matches[0].matched_source}). Quarantine or delete immediately.")

        # Sum Total and Cap at 100
        raw_score = sum(score_breakdown.values())
        overall_score = min(max(raw_score, 0), 100)

        # Categorize
        if overall_score >= 80:
            category = "Critical"
            color = "#EF4444"  # Red
            explanation = "Critical threat level. Severe risks identified including exposed credentials, malicious attachments, or high-confidence phishing."
        elif overall_score >= 60:
            category = "Very High"
            color = "#F97316"  # Orange
            explanation = "Very high risk. Multiple security indicators such as sender domain mismatch, deceptive links, or heavy PII leakage present."
        elif overall_score >= 40:
            category = "High"
            color = "#EAB308"  # Yellow
            explanation = "High risk. Notable privacy or security vulnerabilities detected. Proceed with caution and verify sender integrity."
        elif overall_score >= 20:
            category = "Moderate"
            color = "#3B82F6"  # Blue
            explanation = "Moderate risk. Minor concerns such as remote tracking pixels, missing security headers, or low-level telemetry."
        else:
            category = "Low"
            color = "#10B981"  # Emerald Green
            explanation = "Low risk. No severe threat indicators detected; standard security practices observed."

        if not recommended_actions:
            recommended_actions.append("Standard caution: Email appears benign, but remain vigilant when interacting with external senders.")

        findings_count = {
            "pii": len(pii_findings),
            "phishing": len(phishing_findings),
            "urls": len(suspicious_urls),
            "tracking": len(tracking_findings),
            "headers": len([h for h in header_findings if h.status in ["FAIL", "SOFTFAIL", "SUSPICIOUS"]]),
            "attachments": len([a for a in attachment_findings if a.risk_level in ["CRITICAL", "HIGH", "MEDIUM"]]),
            "threat_intel_matches": len(threat_intel_matches) if threat_intel_matches else 0
        }

        return RiskAssessment(
            overall_score=overall_score,
            risk_category=category,
            category_color=color,
            score_breakdown=score_breakdown,
            score_explanation=explanation,
            findings_count=findings_count,
            recommended_actions=recommended_actions,
            is_heuristic=True,
            disclaimer="Score is an application-specific heuristic calculated by EPA threat rules and not an official certification."
        )
