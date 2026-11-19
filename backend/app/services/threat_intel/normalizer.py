import re
import urllib.parse
from typing import Dict, Any, Optional, List

# Official 10 Incident Categories
INCIDENT_CATEGORIES = [
    "Service Outage",
    "Cyberattack",
    "Data Breach",
    "Ransomware",
    "Data Leak",
    "Phishing Campaign",
    "Malware Campaign",
    "Vulnerability Disclosure",
    "Supply-Chain Compromise",
    "Unverified Threat-Actor Claim"
]

CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

class ThreatIntelNormalizer:
    """Normalizes IOCs, classifications, and incident attributes."""

    @staticmethod
    def normalize_url(url: str) -> Optional[str]:
        """Normalize URL string to lowercased scheme/netloc with preserved path."""
        if not url or not isinstance(url, str):
            return None
        url = url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            return None
        try:
            parsed = urllib.parse.urlparse(url)
            netloc = parsed.netloc.lower()
            return urllib.parse.urlunparse((
                parsed.scheme.lower(),
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ""
            ))
        except Exception:
            return url

    @staticmethod
    def extract_cves(text: str) -> List[str]:
        """Extract uppercase CVE identifiers from text."""
        if not text:
            return []
        matches = CVE_REGEX.findall(text)
        return sorted(list(set(m.upper() for m in matches)))

    @staticmethod
    def classify_incident(title: str, description: str, raw_category: Optional[str] = None) -> str:
        """
        Strictly classify incident into one of the 10 mandated categories.
        Ensures outages are NOT erroneously classified as cyberattacks.
        Ensures unverified dark-web claims are NOT classified as confirmed data breaches.
        """
        combined = f"{title} {description} {raw_category or ''}".lower()

        # Explicit override preservation if raw_category is already an official category
        if raw_category in ["Service Outage", "Data Breach", "Unverified Threat-Actor Claim"]:
            return raw_category

        # 1. Unverified Threat-Actor Claim (Dark-web advertisements, forum claims)
        if any(k in combined for k in [
            "claim", "threat actor claims", "dark web", "darkweb",
            "breachforums", "telegram channel", "actor advertises",
            "alleged leak", "unconfirmed sale"
        ]):
            # If not independently confirmed by company/CISA, label as Unverified Threat-Actor Claim
            if not any(k in combined for k in ["confirmed by", "sec filing", "official disclosure", "vendor confirmed"]):
                return "Unverified Threat-Actor Claim"

        # 2. Service Outage (Infrastructure, DNS, BGP, hardware, routing, power)
        if any(k in combined for k in [
            "service outage", "outage", "service degradation", "routing issue", "infrastructure failure",
            "gateway timeout", "bgp", "dns issue", "elevated error rate", "mitigating error", "service disruption"
        ]):
            # Explicitly check for negation phrases like "not a malicious intrusion", "not a cyberattack"
            has_malicious = any(k in combined for k in ["ransomware", "malware", "ddos", "cyber intrusion", "exfiltration"])
            is_negated = any(n in combined for n in ["not a malicious", "not a cyber", "flawed routing", "internal configuration"])
            if not has_malicious or is_negated:
                return "Service Outage"

        # 3. Ransomware
        if any(k in combined for k in ["ransomware", "blackcat", "alphv", "lockbit", "clop", "encryptor", "double extortion"]):
            return "Ransomware"

        # 4. Supply-Chain Compromise
        if any(k in combined for k in ["supply chain", "supply-chain", "third-party vendor", "dependency breach", "solarwinds", "codecov"]):
            return "Supply-Chain Compromise"

        # 5. Phishing Campaign
        if any(k in combined for k in ["phishing", "credential harvesting", "smishing", "spearphishing", "lure"]):
            return "Phishing Campaign"

        # 6. Malware Campaign
        if any(k in combined for k in ["malware", "infostealer", "trojan", "c2", "command and control", "botnet", "lumma", "redline"]):
            return "Malware Campaign"

        # 7. Vulnerability Disclosure
        if any(k in combined for k in ["cve-", "vulnerability", "advisory", "civn-", "zero-day", "0-day", "rce", "remote code execution"]):
            return "Vulnerability Disclosure"

        # 8. Data Leak (Misconfigured S3 / database without active adversary proof)
        if any(k in combined for k in ["data leak", "misconfigured", "unprotected bucket", "exposed database", "open elasticsearch"]):
            return "Data Leak"

        # 9. Data Breach (Confirmed unauthorized exfiltration/compromise)
        if any(k in combined for k in ["data breach", "exfiltration", "stolen customer", "compromised records", "database stolen"]):
            return "Data Breach"

        # 10. Cyberattack (General DDoS, network intrusion, state actor)
        if any(k in combined for k in ["cyberattack", "ddos", "unauthorized access", "hacked", "intrusion"]):
            return "Cyberattack"

        return raw_category if raw_category in INCIDENT_CATEGORIES else "Cyberattack"
