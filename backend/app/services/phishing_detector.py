import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any, Tuple
from app.schemas.analysis import PhishingFinding, SuspiciousURL
from app.services.email_parser import ParsedEmail

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "rebrand.ly", "tiny.cc", "goo.gl", "trib.al",
    "adf.ly", "bl.ink", "lnkd.in", "s.id", "t.ly", "v.gd"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "buzz",
    "rest", "loan", "fit", "surf", "casa", "country", "link", "party",
    "stream", "trade", "cam", "kim", "mom", "vip"
}

POPULAR_BRANDS = [
    "paypal", "microsoft", "google", "apple", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "citi", "facebook", "instagram",
    "twitter", "linkedin", "dropbox", "dhl", "fedex", "usps"
]

URGENT_PHRASES = [
    (r'(?i)\baccount (?:has been |is )?(?:suspended|locked|terminated|blocked|disabled)\b', "Account Suspension Threat"),
    (r'(?i)\b(?:immediate|urgent) action (?:required|needed)\b', "Urgency Pressure Lure"),
    (r'(?i)\b(?:verify|confirm|validate) your (?:identity|account|credentials|password|email)\b', "Credential Harvesting Prompt"),
    (r'(?i)\bunauthorized (?:access|activity|login) (?:detected|attempt)\b', "Security Scare Tactic"),
    (r'(?i)\bwithin 24 hours\b|\bwithin (?:12|48) hours\b|\bimmediately\b', "Artificial Time Pressure"),
    (r'(?i)\bwire transfer\b|\bpayment overdue\b|\binvoice payment required\b', "Financial Lure"),
    (r'(?i)\byour password will expire\b|\bpassword expiration notice\b', "Password Expiration Scare"),
    (r'(?i)\bclick (?:here|below) to (?:restore|reactivate|verify|login)\b', "Action Redirection Link Lure")
]

def extract_domain(email_or_url: str) -> str:
    """Safely extract lowercase root domain from email address or URL."""
    if not email_or_url:
        return ""
    val = email_or_url.strip().lower()
    
    # If it's an email address
    if "@" in val:
        # Extract between angle brackets if present
        if "<" in val and ">" in val:
            match = re.search(r'<([^>]+)>', val)
            if match:
                val = match.group(1).lower()
        parts = val.split("@")
        return parts[-1].strip(">").strip()
        
    # If it's a URL
    try:
        if not val.startswith("http://") and not val.startswith("https://"):
            val = "http://" + val
        parsed = urlparse(val)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:
        return ""

class PhishingDetectorService:
    @staticmethod
    def analyze_urls(urls: List[str]) -> Tuple[List[SuspiciousURL], List[PhishingFinding]]:
        """Inspect URLs for shorteners, punycode, raw IP hosts, suspicious TLDs, and open redirects."""
        suspicious_list: List[SuspiciousURL] = []
        findings: List[PhishingFinding] = []
        
        seen_domains = set()

        for raw_url in urls:
            try:
                parsed = urlparse(raw_url)
                hostname = parsed.hostname or ""
                domain = hostname.lower()
                
                is_shortener = domain in KNOWN_SHORTENERS
                is_punycode = domain.startswith("xn--") or ".xn--" in domain
                
                # Check for IP address as hostname (e.g., http://192.168.1.1/login)
                is_ip = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain))
                
                # Check suspicious TLD
                tld = domain.split(".")[-1] if "." in domain else ""
                has_suspicious_tld = tld in SUSPICIOUS_TLDS
                
                # Check open redirect query params
                query_params = parse_qs(parsed.query)
                has_redirect = False
                for redirect_key in ["url", "redirect", "next", "goto", "dest", "target", "link"]:
                    if redirect_key in query_params:
                        has_redirect = True
                        break
                        
                risk_factors = []
                if is_shortener:
                    risk_factors.append("URL Shortener conceals true destination")
                if is_punycode:
                    risk_factors.append("Punycode (IDN) detected; possible homograph attack")
                if is_ip:
                    risk_factors.append("Direct IP address used instead of reputable domain")
                if has_suspicious_tld:
                    risk_factors.append(f"Suspicious high-risk top level domain (.{tld})")
                if has_redirect:
                    risk_factors.append("Contains open-redirect parameter (?redirect= / ?url=)")
                    
                # Deceptive subdomain brand impersonation (e.g. paypal.com.something.xyz)
                for brand in POPULAR_BRANDS:
                    if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.net") and not domain.endswith(f"{brand}.org"):
                        risk_factors.append(f"Possible brand impersonation of '{brand}' inside host '{domain}'")

                if risk_factors:
                    suspicious_obj = SuspiciousURL(
                        url=raw_url,
                        domain=domain,
                        is_shortener=is_shortener,
                        is_punycode=is_punycode,
                        is_ip_host=is_ip,
                        has_redirect=has_redirect,
                        suspicious_tld=has_suspicious_tld,
                        risk_factors=risk_factors
                    )
                    suspicious_list.append(suspicious_obj)
                    
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        sev = "critical" if (is_ip or is_punycode or len(risk_factors) >= 2) else "high"
                        findings.append(PhishingFinding(
                            category="url",
                            title=f"Suspicious Destination URL ({domain})",
                            description="; ".join(risk_factors),
                            severity=sev,
                            evidence_masked=f"{raw_url[:40]}... (domain: {domain})",
                            indicators=risk_factors
                        ))
            except Exception:
                continue

        return suspicious_list, findings

    @staticmethod
    def analyze_sender_mismatch(parsed_email: ParsedEmail) -> List[PhishingFinding]:
        """Analyze From vs Reply-To vs Return-Path mismatches."""
        findings: List[PhishingFinding] = []
        
        from_domain = extract_domain(parsed_email.sender)
        reply_to_domain = extract_domain(parsed_email.reply_to) if parsed_email.reply_to else ""
        return_path_domain = extract_domain(parsed_email.return_path) if parsed_email.return_path else ""

        if not from_domain:
            return findings

        # Check From vs Reply-To
        if reply_to_domain and from_domain != reply_to_domain:
            # Common legitimate ESP exceptions (e.g. bounce handlers), but flag if completely different
            is_generic_free_provider = reply_to_domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
            sev = "critical" if is_generic_free_provider else "high"
            
            findings.append(PhishingFinding(
                category="mismatch",
                title="Sender and Reply-To Address Domain Mismatch",
                description=f"The sender claims domain '{from_domain}', but email replies are routed to '{reply_to_domain}'. This is a prime phishing and spoofing indicator.",
                severity=sev,
                evidence_masked=f"From: {from_domain} != Reply-To: {reply_to_domain}",
                indicators=["Domain Mismatch", "Potential Email Impersonation", f"Reply routed to {reply_to_domain}"]
            ))

        # Check Return-Path vs From if Return-Path exists and differs significantly
        if return_path_domain and return_path_domain != from_domain:
            # Check if one is subdomain of another
            if not from_domain.endswith("." + return_path_domain) and not return_path_domain.endswith("." + from_domain):
                # Don't double count if it's already caught by Reply-To, but note it
                findings.append(PhishingFinding(
                    category="mismatch",
                    title="Return-Path Domain Inconsistency",
                    description=f"The Return-Path header ({return_path_domain}) does not align with the Sender domain ({from_domain}).",
                    severity="medium",
                    evidence_masked=f"From: {from_domain} != Return-Path: {return_path_domain}",
                    indicators=["Return-Path Inconsistency"]
                ))

        return findings

    @staticmethod
    def analyze_manipulative_language(body_text: str, subject: str) -> List[PhishingFinding]:
        """Detect urgency, social engineering lures, and psychological pressure tactics."""
        findings: List[PhishingFinding] = []
        full_content = f"{subject}\n{body_text}"
        
        matched_indicators = []
        
        for pattern, label in URGENT_PHRASES:
            matches = list(re.finditer(pattern, full_content))
            if matches:
                sample = matches[0].group(0)
                matched_indicators.append(f"{label}: '{sample}'")

        if matched_indicators:
            sev = "high" if len(matched_indicators) >= 2 else "medium"
            findings.append(PhishingFinding(
                category="urgency",
                title="Social Engineering & High-Pressure Language Detected",
                description="The email utilizes coercive or alarming phrasing designed to provoke hasty user interaction without independent verification.",
                severity=sev,
                evidence_masked="; ".join(matched_indicators[:3]),
                indicators=matched_indicators
            ))

        return findings

    @staticmethod
    def analyze_brand_spoofing(parsed_email: ParsedEmail) -> List[PhishingFinding]:
        """Detect brand impersonation where email text/subject cites major services but sender domain is unrelated."""
        findings: List[PhishingFinding] = []
        from_domain = extract_domain(parsed_email.sender)
        combined_text = f"{parsed_email.subject} {parsed_email.text_content}".lower()

        for brand in POPULAR_BRANDS:
            if brand in combined_text:
                # If brand is explicitly mentioned in subject or multiple times in body
                if brand in parsed_email.subject.lower() or combined_text.count(brand) >= 3:
                    if from_domain and brand not in from_domain:
                        findings.append(PhishingFinding(
                            category="impersonation",
                            title=f"Potential Brand Impersonation ({brand.capitalize()})",
                            description=f"The email prominently refers to {brand.capitalize()}, yet the originating sender domain is '{from_domain}', which is not an authorized domain for this organization.",
                            severity="high",
                            evidence_masked=f"Mentioned Brand: {brand.capitalize()} | Sender Domain: {from_domain}",
                            indicators=[f"Unverified Brand Reference ({brand})", "Origin Domain Discrepancy"]
                        ))
                        break  # Report top primary brand

        return findings

    @classmethod
    def evaluate(cls, parsed_email: ParsedEmail) -> Tuple[List[SuspiciousURL], List[PhishingFinding]]:
        """Run all phishing and social engineering detectors."""
        suspicious_urls, url_findings = cls.analyze_urls(parsed_email.extracted_urls)
        mismatch_findings = cls.analyze_sender_mismatch(parsed_email)
        urgency_findings = cls.analyze_manipulative_language(parsed_email.text_content, parsed_email.subject)
        spoofing_findings = cls.analyze_brand_spoofing(parsed_email)
        
        all_phishing_findings = url_findings + mismatch_findings + urgency_findings + spoofing_findings
        return suspicious_urls, all_phishing_findings
