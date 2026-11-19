import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any
from app.schemas.analysis import TrackingFinding
from app.services.email_parser import ParsedEmail

KNOWN_TRACKING_SERVICES = {
    "sendgrid.net": "SendGrid Email Tracker",
    "ct.sendgrid.net": "SendGrid Click & Open Tracker",
    "list-manage.com": "Mailchimp Open Beacon",
    "mandrillapp.com": "Mandrill Open Tracker",
    "hubspot.com": "HubSpot Marketing Beacon",
    "hs-analytics.net": "HubSpot Analytics Pixel",
    "mixmax.com": "Mixmax Email Read Receipt",
    "yesware.com": "Yesware Read Tracking Pixel",
    "mailtrack.io": "Mailtrack Read Confirmation",
    "mltrk.io": "Mailtrack Beacon",
    "superhuman.com": "Superhuman Read Beacon",
    "streak.com": "Streak CRM Tracking Pixel",
    "mailfoogae.appspot.com": "Streak Web Beacon",
    "salesloft.com": "SalesLoft Tracking Beacon",
    "activehosted.com": "ActiveCampaign Tracking Pixel",
    "rs6.net": "Constant Contact Tracker",
    "marketo.com": "Marketo Tracking Beacon",
    "mktomail.com": "Marketo Tracking Relay",
    "litmus.com": "Litmus Analytics Beacon",
    "cmail19.com": "Campaign Monitor Tracker",
    "cmail20.com": "Campaign Monitor Tracker",
    "klaviyo.com": "Klaviyo Tracking Beacon",
    "customer.io": "Customer.io Tracking Pixel"
}

TRACKING_QUERY_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "recipient_id", "email_id", "uid", "eid", "track", "open", "pixel",
    "tracking_id", "subscriber_id", "mid", "lid"
}

class TrackingDetectorService:
    @staticmethod
    def detect_trackers(parsed_email: ParsedEmail) -> List[TrackingFinding]:
        """Detect tracking pixels, web beacons, remote tracking images, and telemetry parameters."""
        findings: List[TrackingFinding] = []
        seen_urls = set()

        # 1. Analyze <img> elements from email HTML
        for img in parsed_email.extracted_images:
            src = img.get("src", "").strip()
            width = img.get("width", "").strip().lower()
            height = img.get("height", "").strip().lower()
            style = img.get("style", "").strip().lower()
            
            if not src or src.startswith("data:image"):
                continue

            if src in seen_urls:
                continue

            parsed_url = urlparse(src)
            domain = (parsed_url.hostname or "").lower()

            # Check 1: 1x1 Pixel or Zero-dimension detection
            is_zero_dimension = False
            if width in ["0", "1", "0px", "1px"] or height in ["0", "1", "0px", "1px"]:
                is_zero_dimension = True
            elif "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                is_zero_dimension = True
            elif "width:1px" in style or "height:1px" in style or "width: 1px" in style or "height: 1px" in style:
                is_zero_dimension = True

            # Check 2: Known tracking domain match
            matched_service = None
            for track_domain, service_name in KNOWN_TRACKING_SERVICES.items():
                if domain == track_domain or domain.endswith("." + track_domain):
                    matched_service = service_name
                    break

            # Check 3: Suspicious tracking parameters in image URL
            query_params = parse_qs(parsed_url.query)
            has_tracking_param = any(param in TRACKING_QUERY_PARAMS for param in query_params)

            # Check 4: Filename or path hints (e.g. /open.gif, /pixel.png, /track/open)
            path_lower = parsed_url.path.lower()
            has_pixel_path = any(hint in path_lower for hint in ["pixel", "track", "beacon", "open.gif", "tr.gif", "spacer.gif", "blank.gif"])

            # Classification
            if is_zero_dimension:
                seen_urls.add(src)
                service_label = matched_service or "Invisible Tracking Pixel (Web Beacon)"
                findings.append(TrackingFinding(
                    tracking_type="1x1_pixel",
                    tracker_name=service_label,
                    url=src[:120] + ("..." if len(src) > 120 else ""),
                    is_zero_dimension=True,
                    severity="high",
                    description=f"Zero/1-pixel invisible image embedded to covertly monitor when and where you open this email ({service_label})."
                ))
            elif matched_service:
                seen_urls.add(src)
                findings.append(TrackingFinding(
                    tracking_type="esp_tracker",
                    tracker_name=matched_service,
                    url=src[:120] + ("..." if len(src) > 120 else ""),
                    is_zero_dimension=False,
                    severity="medium",
                    description=f"Remote telemetry image linked to commercial tracking service: {matched_service}."
                ))
            elif has_pixel_path and has_tracking_param:
                seen_urls.add(src)
                findings.append(TrackingFinding(
                    tracking_type="web_beacon",
                    tracker_name="Custom Telemetry Beacon",
                    url=src[:120] + ("..." if len(src) > 120 else ""),
                    is_zero_dimension=False,
                    severity="medium",
                    description="Remote beacon image containing recipient tracking identifiers in query parameters."
                ))

        # 2. Check general extracted URLs for heavy telemetry parameters
        for url in parsed_email.extracted_urls:
            if url in seen_urls:
                continue
            parsed_u = urlparse(url)
            domain_u = (parsed_u.hostname or "").lower()
            
            # Check known tracking relay domains in hyperlinks
            for track_domain, service_name in KNOWN_TRACKING_SERVICES.items():
                if domain_u == track_domain or domain_u.endswith("." + track_domain):
                    seen_urls.add(url)
                    findings.append(TrackingFinding(
                        tracking_type="esp_tracker",
                        tracker_name=service_name,
                        url=url[:120] + ("..." if len(url) > 120 else ""),
                        is_zero_dimension=False,
                        severity="low",
                        description=f"Hyperlink redirects through marketing tracking gateway ({service_name}) before landing on destination."
                    ))
                    break

        return findings
