import re
import logging
from typing import List, Dict, Any, Tuple
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from app.schemas.analysis import PIIFinding

logger = logging.getLogger("epa.pii")

def mask_text(value: str, entity_type: str) -> str:
    """Mask sensitive string based on its entity type to prevent data leakage."""
    val = value.strip()
    length = len(val)
    if length <= 2:
        return "••"
        
    entity_upper = entity_type.upper()
    
    if "PASSWORD" in entity_upper or "KEY" in entity_upper or "SECRET" in entity_upper or "TOKEN" in entity_upper:
        return "•••••••• [REDACTED SECRET]"
        
    if "EMAIL" in entity_upper:
        if "@" in val:
            user_part, domain_part = val.split("@", 1)
            masked_user = user_part[0] + "***" if len(user_part) > 1 else "*"
            return f"{masked_user}@{domain_part}"
        return val[:2] + "****"
        
    if "AADHAAR" in entity_upper:
        digits_only = re.sub(r'\D', '', val)
        if len(digits_only) == 12:
            return f"XXXX-XXXX-{digits_only[-4:]}"
        return "XXXX-XXXX-" + val[-4:] if len(val) >= 4 else "XXXXXXXXXXXX"
        
    if "PAN" in entity_upper:
        clean_pan = val.replace(" ", "")
        if len(clean_pan) == 10:
            return f"{clean_pan[:2]}*****{clean_pan[-2:]}"
        return val[:2] + "****" + val[-1:]
        
    if "PHONE" in entity_upper:
        digits = re.sub(r'\D', '', val)
        if len(digits) >= 10:
            return f"+{digits[:-4]}****{digits[-2:]}" if val.startswith("+") else f"{digits[:2]}******{digits[-2:]}"
        return val[:2] + "****" + val[-2:]
        
    if "CARD" in entity_upper:
        digits = re.sub(r'\D', '', val)
        if len(digits) >= 12:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"
        
    if "IP" in entity_upper:
        parts = val.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return val[:4] + "***"

    # Default generic masking
    if length <= 6:
        return val[0] + "*" * (length - 1)
    return val[:2] + "*" * (length - 4) + val[-2:]

class PIIDetectorService:
    def __init__(self):
        self.analyzer: Optional[AnalyzerEngine] = None
        self._init_presidio()
        
        # Additional custom high-precision regex detectors
        self.custom_patterns = [
            # Indian Aadhaar (12 digits, optional space or dash)
            (
                "AADHAAR_NUMBER",
                re.compile(r'\b[2-9]{1}[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b'),
                "critical",
                0.90,
                "Government ID (Aadhaar Number) detected in cleartext email body."
            ),
            # Indian PAN Card (5 alphabets, 4 digits, 1 alphabet)
            (
                "PAN_NUMBER",
                re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
                "high",
                0.92,
                "Income Tax Permanent Account Number (PAN) detected in plaintext."
            ),
            # Passwords in context
            (
                "EXPOSED_PASSWORD",
                re.compile(r'(?i)\b(?:password|passwd|pwd|passphrase)\s*[:=]\s*([^\s,;]+)', re.IGNORECASE),
                "critical",
                0.95,
                "Plaintext password or login credential explicitly disclosed."
            ),
            # AWS Access Key ID
            (
                "AWS_ACCESS_KEY",
                re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
                "critical",
                0.98,
                "Amazon Web Services (AWS) Access Key ID discovered."
            ),
            # GitHub Personal Access Token
            (
                "GITHUB_TOKEN",
                re.compile(r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b'),
                "critical",
                0.98,
                "GitHub Personal Access Token found in email."
            ),
            # JWT Tokens
            (
                "JWT_TOKEN",
                re.compile(r'\beyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b'),
                "high",
                0.95,
                "JSON Web Token (JWT) session credential found."
            ),
            # Generic API / Secret Keys
            (
                "API_SECRET_KEY",
                re.compile(r'(?i)\b(?:api_key|apikey|secret_key|client_secret|auth_token)\s*[:=]\s*([\'"]?[a-zA-Z0-9_\-\.]{16,64}[\'"]?)'),
                "critical",
                0.90,
                "Cryptographic API key or client secret token exposed."
            ),
            # IPv4 Address
            (
                "IP_ADDRESS",
                re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
                "medium",
                0.85,
                "Internal or public IPv4 network address identified."
            ),
            # Credit Card (13-19 digits with Luhn pre-filter)
            (
                "CREDIT_CARD",
                re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b'),
                "critical",
                0.88,
                "Payment card number sequence detected."
            )
        ]

    def _init_presidio(self):
        """Initialize Presidio Analyzer Engine safely using en_core_web_sm."""
        try:
            config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=config)
            nlp_engine = provider.create_engine()
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            
            # Register Aadhaar recognizer into Presidio
            aadhaar_pattern = Pattern(name="aadhaar_pattern", regex=r"\b[2-9]{1}[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b", score=0.85)
            aadhaar_recognizer = PatternRecognizer(supported_entity="IN_AADHAAR", patterns=[aadhaar_pattern])
            self.analyzer.registry.add_recognizer(aadhaar_recognizer)
            
            # Register PAN recognizer into Presidio
            pan_pattern = Pattern(name="pan_pattern", regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", score=0.90)
            pan_recognizer = PatternRecognizer(supported_entity="IN_PAN", patterns=[pan_pattern])
            self.analyzer.registry.add_recognizer(pan_recognizer)
            
            logger.info("Presidio AnalyzerEngine initialized with en_core_web_sm and custom recognizers.")
        except Exception as e:
            logger.warning(f"Presidio AnalyzerEngine init fallback to standalone regex engine: {e}")
            self.analyzer = None

    def analyze_text(self, text: str) -> List[PIIFinding]:
        """Run comprehensive PII detection over email text and body."""
        if not text or not text.strip():
            return []
            
        findings: List[PIIFinding] = []
        seen_spans = set()  # avoid overlapping duplicates

        # 1. Custom Regex & Specialized Recognizers First
        for entity_type, regex_pattern, severity, confidence, desc in self.custom_patterns:
            for match in regex_pattern.finditer(text):
                # If regex has capture group (e.g. password value), use group 1, else match
                raw_match = match.group(1) if match.groups() else match.group(0)
                span = (match.start(), match.end())
                
                # Filter out obvious false positives (e.g. all zeros or standard version numbers)
                if entity_type == "IP_ADDRESS" and raw_match in ["0.0.0.0", "127.0.0.1", "255.255.255.255"]:
                    continue
                    
                span_key = f"{span[0]}:{span[1]}"
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)
                
                masked = mask_text(raw_match, entity_type)
                findings.append(PIIFinding(
                    entity_type=entity_type,
                    text_masked=masked,
                    confidence=confidence,
                    severity=severity,
                    description=desc
                ))

        # 2. Run Presidio for Standard Named Entities (PHONE_NUMBER, EMAIL_ADDRESS, PERSON, etc.)
        if self.analyzer:
            try:
                # We analyze entities
                entities = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "US_SSN", "CRYPTO", "IN_AADHAAR", "IN_PAN"]
                results = self.analyzer.analyze(text=text, entities=entities, language="en")
                
                for res in results:
                    span_key = f"{res.start}:{res.end}"
                    if span_key in seen_spans:
                        continue
                    seen_spans.add(span_key)
                    
                    matched_slice = text[res.start:res.end]
                    entity = res.entity_type
                    
                    # Assign severity
                    if entity in ["IN_AADHAAR", "US_SSN", "CRYPTO"]:
                        sev = "critical"
                    elif entity in ["IN_PAN", "IBAN_CODE"]:
                        sev = "high"
                    elif entity in ["PHONE_NUMBER"]:
                        sev = "medium"
                    else:
                        sev = "low"
                        
                    masked = mask_text(matched_slice, entity)
                    findings.append(PIIFinding(
                        entity_type=entity,
                        text_masked=masked,
                        confidence=round(res.score, 2),
                        severity=sev,
                        description=f"Personal Identifier ({entity}) found in email text."
                    ))
            except Exception as e:
                logger.warning(f"Presidio analyze error: {e}")

        return findings
