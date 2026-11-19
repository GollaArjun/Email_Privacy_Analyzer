import logging
import re
import ipaddress
import urllib.parse
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger("epa.threat_intel")

# Prohibited private/internal hostnames and cloud metadata addresses (SSRF mitigation)
PROHIBITED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254",
    "metadata.google.internal", "instance-data"
}

class BaseThreatSource(ABC):
    """Abstract base class for all threat intelligence feed integrations."""

    def __init__(
        self,
        source_id: str,
        name: str,
        category: str,
        homepage_url: str,
        feed_url: Optional[str] = None,
        requires_api_key: bool = False,
        api_key_env_var: Optional[str] = None,
        sync_interval_minutes: int = 15,
        timeout_seconds: int = 15,
        max_bytes: int = 15 * 1024 * 1024  # 15MB maximum download size protection
    ):
        self.source_id = source_id
        self.name = name
        self.category = category
        self.homepage_url = homepage_url
        self.feed_url = feed_url
        self.requires_api_key = requires_api_key
        self.api_key_env_var = api_key_env_var
        self.sync_interval_minutes = sync_interval_minutes
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

        self.last_sync: Optional[str] = None
        self.last_status: str = "initialized"  # "healthy", "degraded", "offline", "unauthenticated"
        self.last_error: Optional[str] = None
        self.items_ingested_total: int = 0
        self.cached_results: Optional[Dict[str, Any]] = None

    @abstractmethod
    def fetch_and_sync(self) -> Dict[str, Any]:
        """Fetch remote feed, normalize indicators/incidents, and persist into database."""
        pass

    @classmethod
    def is_safe_external_url(cls, url: str) -> bool:
        """
        SSRF Mitigation: Validates that a target URL is public and does not point to
        loopback, link-local, RFC1918 private subnets, or cloud metadata endpoints.
        """
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme.lower() not in ("http", "https"):
                return False

            hostname = parsed.hostname
            if not hostname:
                return False
            hostname_lower = hostname.lower()

            if hostname_lower in PROHIBITED_HOSTS or hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
                return False

            # Check for direct IP address targets
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return False
            except ValueError:
                # Hostname is a domain name, proceed
                pass

            return True
        except Exception:
            return False

    def get_headers(self) -> Dict[str, str]:
        """Standard safe headers for feed requests with User-Agent."""
        return {
            "User-Agent": "EmailPrivacyAnalyzer-ThreatIntelPlatform/2.0 (+https://github.com/epa-platform)",
            "Accept": "application/json, text/plain, text/csv, application/xml, */*",
        }

    def sanitize_string(self, text: Optional[str], max_length: int = 2000) -> str:
        """Sanitize text to prevent malformed injections, remove non-printable characters, and bound length."""
        if not text:
            return ""
        clean = "".join(ch for ch in text if ch == '\n' or ch == '\t' or (32 <= ord(ch) <= 126 or ord(ch) > 127))
        return clean.strip()[:max_length]

    def to_source_metadata(self) -> Dict[str, Any]:
        """Serializable telemetry record of this intelligence feed."""
        import os
        return {
            "source_id": self.source_id,
            "name": self.name,
            "category": self.category,
            "homepage_url": self.homepage_url,
            "feed_url": self.feed_url,
            "requires_api_key": self.requires_api_key,
            "api_key_configured": bool(self.api_key_env_var and bool(os.environ.get(self.api_key_env_var))),
            "last_sync": self.last_sync,
            "status": self.last_status,
            "last_error": self.last_error,
            "items_ingested_total": self.items_ingested_total,
            "sync_interval_minutes": self.sync_interval_minutes
        }
