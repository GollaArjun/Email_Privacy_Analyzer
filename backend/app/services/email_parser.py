import email
from email import policy
from email.parser import BytesParser, Parser
from email.header import decode_header
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from bs4 import BeautifulSoup

def _decode_header_str(val: Optional[str]) -> str:
    """Decode RFC 2047 / encoded MIME headers safely to unicode."""
    if not val:
        return ""
    try:
        decoded_parts = decode_header(val)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                enc = encoding or "utf-8"
                try:
                    result.append(part.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    result.append(part.decode("latin1", errors="replace"))
            else:
                result.append(str(part))
        return " ".join(result).strip()
    except Exception:
        return str(val).strip()

def _clean_body_text(text: str) -> str:
    """Normalize whitespace and remove null bytes."""
    if not text:
        return ""
    return text.replace("\x00", "").strip()

class ParsedEmail:
    def __init__(self):
        self.sender: str = ""
        self.reply_to: Optional[str] = None
        self.return_path: Optional[str] = None
        self.recipients: List[str] = []
        self.cc: List[str] = []
        self.bcc: List[str] = []
        self.subject: str = ""
        self.date: str = ""
        self.message_id: Optional[str] = None
        self.headers: Dict[str, List[str]] = {}
        self.raw_headers_list: List[Tuple[str, str]] = []
        
        self.text_content: str = ""
        self.html_content: str = ""
        
        # Extracted links & images
        self.extracted_urls: List[str] = []
        self.extracted_images: List[Dict[str, Any]] = []
        
        # Attachments metadata (no executable payloads stored)
        self.attachments: List[Dict[str, Any]] = []
        
    def to_metadata_dict(self) -> Dict[str, Any]:
        body_preview = self.text_content[:250].strip()
        if not body_preview and self.html_content:
            soup = BeautifulSoup(self.html_content, "html.parser")
            body_preview = soup.get_text()[:250].strip()
            
        return {
            "sender": self.sender,
            "reply_to": self.reply_to,
            "recipients": self.recipients,
            "cc": self.cc,
            "bcc": self.bcc,
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "return_path": self.return_path,
            "body_text_length": len(self.text_content),
            "body_preview": body_preview,
            "has_html": bool(self.html_content),
            "has_attachments": len(self.attachments) > 0,
            "attachments_count": len(self.attachments)
        }

class EmailParserService:
    @staticmethod
    def parse_raw_email(content: bytes | str) -> ParsedEmail:
        """Parse raw email bytes or string into structured ParsedEmail object."""
        parsed = ParsedEmail()
        
        if isinstance(content, str):
            msg = Parser(policy=policy.default).parsestr(content)
        else:
            msg = BytesParser(policy=policy.default).parsebytes(content)
            
        # 1. Parse Headers
        for key, value in msg.items():
            parsed.raw_headers_list.append((key, str(value)))
            key_lower = key.lower()
            if key_lower not in parsed.headers:
                parsed.headers[key_lower] = []
            parsed.headers[key_lower].append(str(value))
            
        parsed.sender = _decode_header_str(msg.get("From", "Unknown Sender"))
        parsed.reply_to = _decode_header_str(msg.get("Reply-To")) if msg.get("Reply-To") else None
        parsed.return_path = _decode_header_str(msg.get("Return-Path")) if msg.get("Return-Path") else None
        parsed.subject = _decode_header_str(msg.get("Subject", "(No Subject)"))
        parsed.date = _decode_header_str(msg.get("Date", ""))
        parsed.message_id = _decode_header_str(msg.get("Message-ID")) if msg.get("Message-ID") else None
        
        # Recipients
        to_header = msg.get("To", "")
        if to_header:
            parsed.recipients = [_decode_header_str(addr) for addr in str(to_header).split(",") if addr.strip()]
        
        cc_header = msg.get("Cc", "")
        if cc_header:
            parsed.cc = [_decode_header_str(addr) for addr in str(cc_header).split(",") if addr.strip()]
            
        bcc_header = msg.get("Bcc", "")
        if bcc_header:
            parsed.bcc = [_decode_header_str(addr) for addr in str(bcc_header).split(",") if addr.strip()]

        # 2. Extract Body and Attachments
        text_parts = []
        html_parts = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()
                
                # Check if it's an attachment
                is_attachment = "attachment" in content_disposition.lower() or (filename and "inline" not in content_disposition.lower())
                
                if is_attachment or (filename and content_type not in ["text/plain", "text/html"]):
                    payload_bytes = part.get_payload(decode=True) or b""
                    decoded_filename = _decode_header_str(filename or "unnamed_attachment")
                    
                    md5_h = hashlib.md5(payload_bytes).hexdigest()
                    sha256_h = hashlib.sha256(payload_bytes).hexdigest()
                    
                    ext = ""
                    if "." in decoded_filename:
                        ext = decoded_filename.rsplit(".", 1)[-1].lower()
                        
                    parsed.attachments.append({
                        "filename": decoded_filename,
                        "file_size_bytes": len(payload_bytes),
                        "content_type": content_type,
                        "extension": ext,
                        "md5_hash": md5_h,
                        "sha256_hash": sha256_h,
                        "header_disposition": content_disposition
                    })
                else:
                    if content_type == "text/plain":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            body_payload = part.get_payload(decode=True)
                            if body_payload:
                                text_parts.append(body_payload.decode(charset, errors="replace"))
                        except Exception:
                            text_parts.append(part.get_payload() or "")
                    elif content_type == "text/html":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            body_payload = part.get_payload(decode=True)
                            if body_payload:
                                html_parts.append(body_payload.decode(charset, errors="replace"))
                        except Exception:
                            html_parts.append(part.get_payload() or "")
        else:
            # Single-part email
            content_type = msg.get_content_type()
            try:
                charset = msg.get_content_charset() or "utf-8"
                payload = msg.get_payload(decode=True)
                decoded_payload = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                decoded_payload = str(msg.get_payload())
                
            if content_type == "text/html":
                html_parts.append(decoded_payload)
            else:
                text_parts.append(decoded_payload)

        parsed.text_content = _clean_body_text("\n\n".join(text_parts))
        parsed.html_content = _clean_body_text("\n\n".join(html_parts))
        
        # 3. Extract Links and Images
        EmailParserService._extract_links_and_images(parsed)
        
        return parsed

    @staticmethod
    def _extract_links_and_images(parsed: ParsedEmail):
        """Extract all links and images from both HTML and plain-text body."""
        url_pattern = re.compile(
            r'https?://[a-zA-Z0-9_\-\./\?#=&%+:;,@~]+',
            re.IGNORECASE
        )
        
        found_urls = set()
        
        # Plain text URLs
        if parsed.text_content:
            for match in url_pattern.findall(parsed.text_content):
                clean_url = match.rstrip(".,;)>]\"'")
                found_urls.add(clean_url)
                
        # HTML URLs and Images
        if parsed.html_content:
            try:
                soup = BeautifulSoup(parsed.html_content, "html.parser")
                
                # Links
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http://") or href.startswith("https://"):
                        found_urls.add(href)
                        
                # Images
                for img in soup.find_all("img"):
                    src = img.get("src", "").strip()
                    width = img.get("width", "")
                    height = img.get("height", "")
                    style = img.get("style", "")
                    alt = img.get("alt", "")
                    
                    parsed.extracted_images.append({
                        "src": src,
                        "width": str(width),
                        "height": str(height),
                        "style": str(style),
                        "alt": str(alt)
                    })
                    
                # CSS background-image
                for tag in soup.find_all(style=True):
                    style_val = tag.get("style", "")
                    bg_matches = re.findall(r'url\s*\(\s*[\'"]?(https?://[^\'")]+)[\'"]?\s*\)', style_val, re.IGNORECASE)
                    for bg_url in bg_matches:
                        parsed.extracted_images.append({
                            "src": bg_url,
                            "width": "css",
                            "height": "css",
                            "style": style_val,
                            "alt": "css-background"
                        })
            except Exception:
                pass
                
        parsed.extracted_urls = list(found_urls)
