import logging
import re
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Optional
from app.schemas.analysis import ThreatIntelReport, ThreatIntelMatch, AttachmentFinding, SuspiciousURL
from app.database.mongo import get_indicators_col, get_incidents_col, get_sources_col

logger = logging.getLogger("epa.services.threat_intel_correlator")

# Standard RFC1918 & loopback IP regexes to avoid checking private network hops
PRIVATE_IP_PATTERN = re.compile(
    r'^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3}|'
    r'::1|fe80:)'
)

class ThreatIntelCorrelatorService:
    """Correlates extracted email indicators with real-time threat intelligence feeds."""

    SOURCES_CHECKED = [
        "OpenPhish Community Feed",
        "CISA Known Exploited Vulnerabilities Catalog",
        "Authoritative Cyber Incident & Outage Monitor"
    ]

    @classmethod
    def correlate(
        cls,
        urls: List[str],
        sender_email: str,
        attachment_findings: List[AttachmentFinding],
        suspicious_urls: List[SuspiciousURL]
    ) -> ThreatIntelReport:
        """Query threat intelligence indicators for extracted URLs, domains, and attachment hashes."""
        now_iso = datetime.now(timezone.utc).isoformat()
        indicators_col = get_indicators_col()
        incidents_col = get_incidents_col()

        matches: List[ThreatIntelMatch] = []
        scanned_count = 0
        seen_match_values: Set[str] = set()

        # 1. Normalize and check URLs
        normalized_urls: Set[str] = set()
        domains_to_check: Set[str] = set()

        for u in urls:
            u_clean = u.strip()
            if not u_clean or not (u_clean.startswith("http://") or u_clean.startswith("https://")):
                continue
            normalized_urls.add(u_clean)
            try:
                parsed = urllib.parse.urlparse(u_clean)
                host = parsed.netloc.lower().split(":")[0]
                if host and "." in host:
                    domains_to_check.add(host)
            except Exception:
                pass

        # Also extract sender domain
        if sender_email and "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].strip().lower().rstrip(">")
            if sender_domain and "." in sender_domain:
                domains_to_check.add(sender_domain)

        scanned_count += len(normalized_urls) + len(domains_to_check)

        # 2. Match exact URLs against threat_indicators (e.g. OpenPhish)
        for u in normalized_urls:
            if u in seen_match_values:
                continue

            # Query exact URL match
            ind_record = indicators_col.find_one({"indicator_value": u}, {"_id": 0})
            if ind_record:
                seen_match_values.add(u)
                matches.append(
                    ThreatIntelMatch(
                        indicator_value=u,
                        indicator_type="URL",
                        matched_source=ind_record.get("source", "OpenPhish"),
                        source_url=ind_record.get("source_url", "https://openphish.com"),
                        threat_type=ind_record.get("threat_type", "Phishing"),
                        severity=ind_record.get("severity", "CRITICAL"),
                        confidence=ind_record.get("confidence", "Confirmed"),
                        first_seen=ind_record.get("first_seen"),
                        last_seen=ind_record.get("last_seen"),
                        explanation=f"Exact URL verified as active credential-theft lure in {ind_record.get('source', 'OpenPhish')} feed.",
                        reputation_verdict="Confirmed Malicious Phishing URL"
                    )
                )

        # 3. Match Domains against threat_indicators & incidents
        for dom in domains_to_check:
            if dom in seen_match_values:
                continue

            dom_record = indicators_col.find_one({"domain": dom}, {"_id": 0})
            if dom_record and dom not in seen_match_values:
                seen_match_values.add(dom)
                matches.append(
                    ThreatIntelMatch(
                        indicator_value=dom,
                        indicator_type="DOMAIN",
                        matched_source=dom_record.get("source", "OpenPhish"),
                        source_url=dom_record.get("source_url", "https://openphish.com"),
                        threat_type=dom_record.get("threat_type", "Phishing"),
                        severity="HIGH",
                        confidence=dom_record.get("confidence", "Confirmed"),
                        first_seen=dom_record.get("first_seen"),
                        last_seen=dom_record.get("last_seen"),
                        explanation=f"Domain host '{dom}' hosts verified active phishing infrastructure.",
                        reputation_verdict="Deceptive Infrastructure Host"
                    )
                )

            # Check if domain or sender company is linked to recent cyber incident / breach
            inc_match = incidents_col.find_one({
                "$or": [
                    {"company": {"$regex": f"\\b{re.escape(dom.split('.')[0])}\\b", "$options": "i"}},
                    {"iocs": {"$regex": re.escape(dom), "$options": "i"}}
                ]
            }, {"_id": 0})

            if inc_match and dom not in seen_match_values:
                seen_match_values.add(dom)
                cat = inc_match.get("category", "Cyberattack")
                matches.append(
                    ThreatIntelMatch(
                        indicator_value=dom,
                        indicator_type="DOMAIN",
                        matched_source=inc_match.get("source_publication", "Cyber Incident Monitor"),
                        source_url=inc_match.get("direct_source_link"),
                        threat_type=cat,
                        severity="HIGH" if cat in ["Ransomware", "Data Breach", "Phishing Campaign"] else "MEDIUM",
                        confidence=inc_match.get("verification_status", "Reported"),
                        first_seen=inc_match.get("date_reported"),
                        last_seen=inc_match.get("last_updated"),
                        explanation=f"Domain or entity corresponds to tracked security event: {inc_match.get('title')}",
                        reputation_verdict=f"Associated with {cat}"
                    )
                )

        # 4. Check Attachment Hashes (SHA-256)
        for att in attachment_findings:
            scanned_count += 1
            h = att.sha256_hash
            if not h or h in seen_match_values:
                continue

            ind_hash = indicators_col.find_one({"indicator_value": h}, {"_id": 0})
            if ind_hash:
                seen_match_values.add(h)
                matches.append(
                    ThreatIntelMatch(
                        indicator_value=f"{att.filename} ({h[:12]}...)",
                        indicator_type="HASH",
                        matched_source=ind_hash.get("source", "Threat Intelligence Repository"),
                        source_url=ind_hash.get("source_url"),
                        threat_type="Malware Binary",
                        severity="CRITICAL",
                        confidence="Confirmed",
                        first_seen=ind_hash.get("first_seen"),
                        last_seen=ind_hash.get("last_seen"),
                        explanation=f"Attachment SHA256 hash matches known malware payload: {att.filename}",
                        reputation_verdict="Confirmed Malicious File Hash"
                    )
                )

        # 5. Formulate final verdict
        if matches:
            status = "MATCHES_FOUND"
            verdict_summary = f"{len(matches)} threat indicator(s) confirmed in active cybersecurity intelligence feeds."
        else:
            status = "NO_MATCH_FOUND"
            # Prompt requirement: show "No match found in checked sources" rather than "Safe"
            verdict_summary = f"No match found in checked sources ({', '.join(cls.SOURCES_CHECKED)})."

        return ThreatIntelReport(
            indicators_scanned_count=scanned_count,
            matches_count=len(matches),
            status=status,
            verdict_summary=verdict_summary,
            matches=matches,
            sources_checked=cls.SOURCES_CHECKED,
            timestamp=now_iso
        )
