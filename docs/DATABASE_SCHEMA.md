# Email Privacy Analyzer (EPA) — Database Schema & Data Models

The system uses **MongoDB** (with automatic fallback to `mongomock` in local development if no running MongoDB instance is detected). All database access is encapsulated inside `backend/app/database/mongo.py`.

---

## 1. Collections Overview

The database contains four primary collections:

| Collection Name | Purpose | Key Indexes |
|---|---|---|
| `users` | Security operator accounts and master credentials | `user_id` (unique), `email` (unique) |
| `reports` | Inbound email analysis reports and threat telemetry | `report_id` (unique), `user_id`, `created_at` |
| `gmail_connections` | Encrypted OAuth 2.0 refresh tokens for Gmail API | `user_id` (unique) |
| `settings` | Operator preferences, AI configuration, and retention | `user_id` (unique) |

---

## 2. Document Schemas

### A. `users` Collection

```json
{
  "_id": ObjectId("6654b1f..."),
  "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "name": "Arjun Sharma",
  "email": "arjun@example.com",
  "password_hash": "$2b$12$K8...",
  "created_at": "2026-11-18T16:00:00Z"
}
```

- `password_hash`: Salted and hashed using `bcrypt` (12 rounds).
- `user_id`: UUIDv4 string, used as foreign key in all other collections.

---

### B. `reports` Collection

```json
{
  "_id": ObjectId("6654b20..."),
  "report_id": "a5c7f8e1-0d2b-4e89-a1b2-c3d4e5f6a7b8",
  "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "created_at": "2026-11-18T16:05:00Z",
  "email_metadata": {
    "sender": "Security Team <security@paypa1-update.com>",
    "recipient": "user@enterprise.com",
    "subject": "URGENT: Verify Your Account Immediately",
    "date": "Wed, 18 Nov 2026 15:45:00 GMT",
    "message_id": "<20261118154500.12345@paypa1-update.com>",
    "has_attachments": true,
    "attachment_count": 1
  },
  "findings": {
    "pii_findings": [
      {
        "type": "PHONE_NUMBER",
        "severity": "medium",
        "description": "Exposed contact number detected in email body",
        "evidence": "+1 555-***-9821",
        "recommendation": "Redact contact details prior to external forwarding."
      }
    ],
    "phishing_findings": [
      {
        "type": "TYPOSQUATTING_DOMAIN",
        "severity": "critical",
        "description": "Suspicious lookalike domain detected ('paypa1')",
        "evidence": "paypa1-update.com (lookalike for paypal.com)",
        "recommendation": "Block domain at enterprise mail gateway and delete message."
      }
    ],
    "url_findings": [
      {
        "url": "http://192.168.1.100/verify-login",
        "is_suspicious": true,
        "indicators": ["IP-based URL", "Insecure HTTP scheme"]
      }
    ],
    "tracking_findings": [
      {
        "type": "TRACKING_PIXEL",
        "dimensions": "1x1",
        "url": "https://sendgrid.net/wf/open?upn=...",
        "is_zero_dimension": true
      }
    ],
    "header_findings": [
      {
        "check": "SPF",
        "status": "FAIL",
        "severity": "high",
        "details": "Sender IP not permitted by domain SPF policy."
      }
    ],
    "attachment_findings": [
      {
        "filename": "Invoice_Statement.pdf.exe",
        "risk_level": "CRITICAL",
        "indicators": ["Double extension executable (.pdf.exe)", "PE executable binary header detected"]
      }
    ]
  },
  "risk_assessment": {
    "overall_score": 85,
    "risk_category": "Critical",
    "category_color": "#EF4444",
    "score_explanation": "Critical security threats detected including suspicious domain impersonation and dangerous executable attachment.",
    "disclaimer": "Heuristic risk score computed for cybersecurity evaluation.",
    "score_breakdown": {
      "credential_exposure": 0,
      "pii_exposure": 12,
      "phishing_indicators": 35,
      "suspicious_urls": 15,
      "tracking_mechanisms": 5,
      "attachment_risks": 40,
      "header_issues": 18
    },
    "recommended_actions": [
      "Quarantine message immediately",
      "Do not open attachment 'Invoice_Statement.pdf.exe'",
      "Submit sender domain 'paypa1-update.com' to security blocklist"
    ]
  },
  "ai_assessment": {
    "engine": "Ollama / llama3",
    "summary": "This email exhibits classic social engineering tactics aimed at harvesting credentials under the guise of PayPal account maintenance.",
    "threat_level": "Severe",
    "suggested_response": "Report to internal SOC and purge from mailbox."
  }
}
```

---

### C. `gmail_connections` Collection

```json
{
  "_id": ObjectId("6654b21..."),
  "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "encrypted_refresh_token": "gAAAAABmN...",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "connected_at": "2026-11-18T16:10:00Z",
  "email": "analyst@gmail.com"
}
```

- `encrypted_refresh_token`: Stored encrypted at rest using AES-128 via `Fernet` symmetric encryption. The key is managed through `ENCRYPTION_KEY` in environment configuration. Plaintext OAuth tokens are never logged or stored.

---

### D. `settings` Collection

```json
{
  "_id": ObjectId("6654b22..."),
  "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "ai_enabled": true,
  "ollama_model": "llama3",
  "retention_period_days": 30,
  "mask_pii_in_reports": true,
  "notification_preferences": {
    "high_risk_alerts": true,
    "weekly_digest": false,
    "phishing_alerts": true
  },
  "updated_at": "2026-11-18T16:15:00Z"
}
```

---

## 3. Privacy & Sanitization Policy

1. **Zero Raw Body Storage**: The raw text or HTML body of scanned emails is never permanently committed to the database. Only extracted, redacted security findings and structured metadata are retained.
2. **Credential Redaction**: Passwords, API keys, Aadhaar numbers, and PAN identifiers are always passed through the PII masking layer before storage.
3. **Data Retention Lifecycle**: The `retention_period_days` setting governs automatic purging of reports older than the designated interval.
