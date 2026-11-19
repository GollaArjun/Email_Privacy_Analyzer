import re
from typing import List, Dict, Any, Optional
from app.schemas.analysis import HeaderSecurityFinding
from app.services.email_parser import ParsedEmail

class HeaderAnalyzerService:
    @staticmethod
    def analyze_headers(parsed_email: ParsedEmail) -> List[HeaderSecurityFinding]:
        """Analyze email security headers for SPF, DKIM, DMARC, Received hops, and Return-Path."""
        findings: List[HeaderSecurityFinding] = []
        headers = parsed_email.headers

        # 1. Inspect Authentication-Results header
        auth_results_raw = " ".join(headers.get("authentication-results", [])).lower()
        received_spf_raw = " ".join(headers.get("received-spf", [])).lower()
        dkim_sig = headers.get("dkim-signature", [])

        # --- SPF Analysis ---
        spf_status = "UNVERIFIED"
        spf_summary = "SPF record not explicitly validated in email headers"
        spf_sev = "medium"
        
        if "spf=pass" in auth_results_raw or "pass" in received_spf_raw:
            spf_status = "PASS"
            spf_summary = "Sender Policy Framework (SPF) validation passed."
            spf_sev = "low"
        elif "spf=fail" in auth_results_raw or "fail" in received_spf_raw:
            spf_status = "FAIL"
            spf_summary = "SPF validation failed: Sending server is unauthorized for this sender domain."
            spf_sev = "high"
        elif "spf=softfail" in auth_results_raw or "softfail" in received_spf_raw:
            spf_status = "SOFTFAIL"
            spf_summary = "SPF softfail: Sending host is probably not authorized by the domain administrator."
            spf_sev = "medium"
        elif "spf=neutral" in auth_results_raw or "neutral" in received_spf_raw:
            spf_status = "NEUTRAL"
            spf_summary = "SPF returned neutral: Domain owner did not assert whether sender host is authorized."
            spf_sev = "low"
        elif "spf=none" in auth_results_raw:
            spf_status = "NONE"
            spf_summary = "No SPF record published for this sender domain."
            spf_sev = "medium"

        findings.append(HeaderSecurityFinding(
            header_name="SPF (Sender Policy Framework)",
            value_summary=spf_status,
            status=spf_status,
            severity=spf_sev,
            explanation=spf_summary
        ))

        # --- DKIM Analysis ---
        dkim_status = "UNVERIFIED"
        dkim_summary = "DKIM cryptographic signature verification not declared in Authentication-Results."
        dkim_sev = "medium"

        if "dkim=pass" in auth_results_raw:
            dkim_status = "PASS"
            dkim_summary = "DKIM cryptographic signature verified: Message body and headers unaltered in transit."
            dkim_sev = "low"
        elif "dkim=fail" in auth_results_raw:
            dkim_status = "FAIL"
            dkim_summary = "DKIM verification failed: Message contents may have been tampered with or signature is invalid."
            dkim_sev = "critical"
        elif dkim_sig:
            dkim_status = "PRESENT_UNVERIFIED"
            dkim_summary = "DKIM-Signature header present, but receiving MTA did not record validation result in Authentication-Results."
            dkim_sev = "low"
        else:
            dkim_status = "NONE"
            dkim_summary = "No DKIM signature found on email. Lack of cryptographic integrity verification."
            dkim_sev = "medium"

        findings.append(HeaderSecurityFinding(
            header_name="DKIM (DomainKeys Identified Mail)",
            value_summary=dkim_status,
            status=dkim_status,
            severity=dkim_sev,
            explanation=dkim_summary
        ))

        # --- DMARC Analysis ---
        dmarc_status = "UNVERIFIED"
        dmarc_summary = "DMARC policy status not explicitly evaluated in incoming Authentication-Results header."
        dmarc_sev = "medium"

        if "dmarc=pass" in auth_results_raw:
            dmarc_status = "PASS"
            dmarc_summary = "DMARC policy passed: Both SPF/DKIM alignment and sender identity validated."
            dmarc_sev = "low"
        elif "dmarc=fail" in auth_results_raw:
            dmarc_status = "FAIL"
            dmarc_summary = "DMARC policy check failed: Serious domain spoofing or policy rejection risk."
            dmarc_sev = "critical"
        elif "dmarc=none" in auth_results_raw:
            dmarc_status = "NONE"
            dmarc_summary = "No DMARC policy defined by sender domain."
            dmarc_sev = "medium"

        findings.append(HeaderSecurityFinding(
            header_name="DMARC Policy Compliance",
            value_summary=dmarc_status,
            status=dmarc_status,
            severity=dmarc_sev,
            explanation=dmarc_summary
        ))

        # --- Received Hops Analysis ---
        received_headers = headers.get("received", [])
        hops_count = len(received_headers)
        if hops_count > 0:
            status_hop = "NORMAL"
            sev_hop = "low"
            exp_hop = f"Message traversed {hops_count} intermediate Mail Transfer Agent (MTA) relay hop(s)."
            if hops_count > 10:
                status_hop = "SUSPICIOUS"
                sev_hop = "medium"
                exp_hop = f"Unusually high number of MTA relays ({hops_count} hops). Potential proxy chaining or routing loop."
            findings.append(HeaderSecurityFinding(
                header_name="Received MTA Hops",
                value_summary=f"{hops_count} Relay Hop(s)",
                status=status_hop,
                severity=sev_hop,
                explanation=exp_hop
            ))
        else:
            findings.append(HeaderSecurityFinding(
                header_name="Received MTA Hops",
                value_summary="Missing",
                status="SUSPICIOUS",
                severity="medium",
                explanation="No 'Received' headers found. Email headers appear truncated or synthesized."
            ))

        # --- Message-ID check ---
        msg_id = parsed_email.message_id
        if not msg_id:
            findings.append(HeaderSecurityFinding(
                header_name="Message-ID Header",
                value_summary="Missing",
                status="SUSPICIOUS",
                severity="medium",
                explanation="Standard RFC 5322 Message-ID header is absent. Typical in poorly crafted spam or automated generators."
            ))
        else:
            findings.append(HeaderSecurityFinding(
                header_name="Message-ID Header",
                value_summary=msg_id[:35] + ("..." if len(msg_id) > 35 else ""),
                status="PASS",
                severity="low",
                explanation="RFC 5322 globally unique Message-ID header present."
            ))

        return findings
