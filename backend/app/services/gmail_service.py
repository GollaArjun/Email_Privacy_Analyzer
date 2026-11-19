import os
import base64
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import requests
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from app.config import settings
from app.security.crypto import encrypt_token, decrypt_token
from app.database.mongo import get_connections_col
from app.schemas.analysis import GmailMessageSummary

logger = logging.getLogger("epa.gmail")

GMAIL_READONLY_SCOPE = ["https://www.googleapis.com/auth/gmail.readonly"]

# Synthetic realistic inbox sample for demo / unconfigured mode
DEMO_MESSAGES = [
    {
        "id": "msg_demo_001",
        "thread_id": "thread_001",
        "sender": "Security Team <security-alert@micros0ft-verify.xyz>",
        "subject": "CRITICAL: Suspicious sign-in detected for your account",
        "date": "Today, 14:22",
        "snippet": "We noticed an unauthorized sign-in from an unknown IP in Moscow, Russia. Your account will be locked within 24 hours unless verified...",
        "raw_eml": """From: "Microsoft Security Alert" <security-alert@micros0ft-verify.xyz>
Reply-To: "Verification Desk" <urgent-verify@mail-portal.top>
To: target-user@company.com
Subject: CRITICAL: Suspicious sign-in detected for your account
Date: Sun, 15 Nov 2026 14:22:10 +0000
Message-ID: <threat-20261115-001@micros0ft-verify.xyz>
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail

Dear Customer,

We detected an unauthorized sign-in attempt from IP 185.220.101.5. Immediate action required.
Your account will be suspended within 24 hours if you do not confirm your credentials.

Click here to verify: http://192.168.1.100/login?redirect=http://portal.xyz

Your temporary reset passcode is: TempPassword987!
Do not share this with anyone.
"""
    },
    {
        "id": "msg_demo_002",
        "thread_id": "thread_002",
        "sender": "HR Payroll <hr@acme-corp.internal>",
        "subject": "Confidential: Updated Compensation & Tax Identification Records",
        "date": "Yesterday, 09:15",
        "snippet": "Please find attached the compensation records for our upcoming review. Attached are employee Aadhaar and PAN numbers for audit...",
        "raw_eml": """From: HR Payroll <hr@acme-corp.internal>
To: finance@acme-corp.internal
Subject: Confidential: Updated Compensation & Tax Identification Records
Date: Sat, 14 Nov 2026 09:15:00 +0000
Message-ID: <hr-data-002@acme-corp.internal>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi Finance Team,

Please review the verified credentials for employee ID 4082:
Aadhaar Number: 4582 9102 3847
PAN Number: ABCDE1234F
Registered Phone: +91 9876543210
Emergency API Token: ghp_aB89xKmQz109PqRstUvwXyZ4567890abcdef

Let me know if further tax clearance is required.
"""
    },
    {
        "id": "msg_demo_003",
        "thread_id": "thread_003",
        "sender": "Marketing Weekly <news@retail-promo.com>",
        "subject": "Exclusive Weekend Flash Deals Just for You!",
        "date": "13 Nov 2026",
        "snippet": "Check out our latest flash sale! Click here to view items. Special 25% discounts available all weekend...",
        "raw_eml": """From: Marketing Weekly <news@retail-promo.com>
To: shopper@domain.com
Subject: Exclusive Weekend Flash Deals Just for You!
Date: Fri, 13 Nov 2026 11:00:00 +0000
Content-Type: text/html; charset=utf-8
Message-ID: <promo-003@retail-promo.com>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

<html>
<body>
<h1>Weekend Flash Deals!</h1>
<p>Enjoy our top discounts across all store categories.</p>
<a href="https://retail-promo.com/deals?utm_source=email&recipient_id=user982">Shop Now</a>
<img src="https://sendgrid.net/wf/open?upn=tracker99201" width="1" height="1" style="display:none;" alt="tracker" />
</body>
</html>
"""
    }
]

class GmailService:
    @staticmethod
    def is_configured() -> bool:
        """Check if Google OAuth Client ID and Secret are provided in configuration."""
        return bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET)

    @classmethod
    def get_auth_url(cls, state: str) -> str:
        """Generate Google OAuth 2.0 authorization URL with minimum read-only scope and CSRF state token."""
        if not cls.is_configured():
            # Return demo callback URL
            return f"{settings.GOOGLE_REDIRECT_URI}?code=demo_auth_code&state={state}"

        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=GMAIL_READONLY_SCOPE,
            redirect_uri=settings.GOOGLE_REDIRECT_URI
        )
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state,
            prompt='consent'
        )
        return authorization_url

    @classmethod
    def exchange_code(cls, user_id: str, code: str) -> bool:
        """Exchange authorization code for refresh token and store encrypted token in database."""
        if not cls.is_configured() or code == "demo_auth_code":
            # Save synthetic active connection for demo
            col = get_connections_col()
            col.update_one(
                {"user_id": user_id},
                {"$set": {
                    "user_id": user_id,
                    "encrypted_refresh_token": encrypt_token("demo_refresh_token_12345"),
                    "scopes": GMAIL_READONLY_SCOPE,
                    "is_demo": True,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }},
                upsert=True
            )
            return True

        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=GMAIL_READONLY_SCOPE,
            redirect_uri=settings.GOOGLE_REDIRECT_URI
        )

        flow.fetch_token(code=code)
        credentials = flow.credentials
        refresh_token = credentials.refresh_token

        if refresh_token:
            encrypted_rt = encrypt_token(refresh_token)
            col = get_connections_col()
            col.update_one(
                {"user_id": user_id},
                {"$set": {
                    "user_id": user_id,
                    "encrypted_refresh_token": encrypted_rt,
                    "scopes": GMAIL_READONLY_SCOPE,
                    "is_demo": False,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }},
                upsert=True
            )
            return True
        return False

    @classmethod
    def get_connection_status(cls, user_id: str) -> Dict[str, Any]:
        """Check if user has an active Gmail authorization."""
        col = get_connections_col()
        doc = col.find_one({"user_id": user_id})
        if not doc:
            return {"connected": False, "is_demo": False, "configured": cls.is_configured()}
        return {
            "connected": True,
            "is_demo": doc.get("is_demo", False),
            "created_at": doc.get("created_at"),
            "scopes": doc.get("scopes", []),
            "configured": cls.is_configured()
        }

    @classmethod
    def disconnect(cls, user_id: str) -> bool:
        """Revoke and delete stored Gmail connection tokens."""
        col = get_connections_col()
        doc = col.find_one({"user_id": user_id})
        if doc and not doc.get("is_demo"):
            raw_token = decrypt_token(doc.get("encrypted_refresh_token", ""))
            if raw_token:
                try:
                    requests.post('https://oauth2.googleapis.com/revoke',
                        params={'token': raw_token},
                        headers={'content-type': 'application/x-www-form-urlencoded'},
                        timeout=5
                    )
                except Exception as e:
                    logger.warning(f"Error revoking token with Google: {e}")

        result = col.delete_one({"user_id": user_id})
        return result.deleted_count > 0

    @classmethod
    def list_messages(cls, user_id: str, max_results: int = 10) -> List[GmailMessageSummary]:
        """List recent inbox messages (read-only snippets and metadata)."""
        status_info = cls.get_connection_status(user_id)
        if not status_info["connected"]:
            return []

        if status_info["is_demo"] or not cls.is_configured():
            return [
                GmailMessageSummary(
                    id=m["id"],
                    thread_id=m["thread_id"],
                    sender=m["sender"],
                    subject=m["subject"],
                    date=m["date"],
                    snippet=m["snippet"]
                ) for m in DEMO_MESSAGES
            ]

        # Live Google API call
        col = get_connections_col()
        doc = col.find_one({"user_id": user_id})
        refresh_token = decrypt_token(doc.get("encrypted_refresh_token", ""))

        creds = Credentials(
            None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=GMAIL_READONLY_SCOPE
        )

        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=max_results, q='in:inbox').execute()
        messages = results.get('messages', [])

        summaries = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From', 'Subject', 'Date']).execute()
            headers = {h['name'].lower(): h['value'] for h in msg_data.get('payload', {}).get('headers', [])}
            summaries.append(GmailMessageSummary(
                id=msg['id'],
                thread_id=msg['threadId'],
                sender=headers.get('from', 'Unknown'),
                subject=headers.get('subject', '(No Subject)'),
                date=headers.get('date', ''),
                snippet=msg_data.get('snippet', '')
            ))
        return summaries

    @classmethod
    def get_raw_message_rfc822(cls, user_id: str, message_id: str) -> Optional[str]:
        """Fetch RFC822 raw message string for analysis."""
        # Check demo
        for m in DEMO_MESSAGES:
            if m["id"] == message_id:
                return m["raw_eml"]

        col = get_connections_col()
        doc = col.find_one({"user_id": user_id})
        if not doc:
            return None

        refresh_token = decrypt_token(doc.get("encrypted_refresh_token", ""))
        creds = Credentials(
            None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=GMAIL_READONLY_SCOPE
        )

        service = build('gmail', 'v1', credentials=creds)
        msg_data = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        raw_b64 = msg_data.get('raw', '')
        if raw_b64:
            return base64.urlsafe_b64decode(raw_b64).decode('utf-8', errors='replace')
        return None
