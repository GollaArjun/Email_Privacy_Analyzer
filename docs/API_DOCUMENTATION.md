# Email Privacy Analyzer (EPA) — REST API Documentation

This document describes all REST API endpoints provided by the Email Privacy Analyzer backend service.

**Base URL**: `http://localhost:8000` (development) or configured production domain.  
**Interactive Docs**: `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc).

---

## 1. System & Telemetry Endpoints

### `GET /api/health`
Checks system telemetry, connected services, and database status.

- **Auth Required**: No
- **Response `200 OK`**:
  ```json
  {
    "status": "healthy",
    "app_name": "Email Privacy Analyzer",
    "version": "1.0.0",
    "environment": "development",
    "timestamp": "2026-11-18T16:30:00Z",
    "database": {
      "connected": true,
      "mode": "mongodb-live"
    },
    "services": {
      "presidio_analyzer": "active",
      "ollama_llm": "online",
      "google_oauth": "simulation-demo-mode"
    }
  }
  ```

---

## 2. Authentication Endpoints

### `POST /api/auth/register`
Creates a new security operator account.

- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "name": "Alex Vance",
    "email": "alex@cyberdefense.org",
    "password": "SecuredPassword123"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "user": {
      "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "name": "Alex Vance",
      "email": "alex@cyberdefense.org"
    }
  }
  ```

### `POST /api/auth/login`
Authenticates with email and password and returns a JWT access token.

- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "email": "alex@cyberdefense.org",
    "password": "SecuredPassword123"
  }
  ```
- **Response `200 OK`**: Returns `TokenResponse` with `access_token` and `user`.

### `GET /api/auth/me`
Retrieves operator profile and scanning metrics.

- **Auth Required**: Yes (`Bearer <token>`)
- **Response `200 OK`**:
  ```json
  {
    "user_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "name": "Alex Vance",
    "email": "alex@cyberdefense.org",
    "created_at": "2026-11-18T16:00:00Z",
    "stats": {
      "total_scans": 14,
      "high_risk_scans": 3
    }
  }
  ```

### `PUT /api/auth/me`
Updates operator profile information (display name).

- **Auth Required**: Yes (`Bearer <token>`)
- **Request Body**:
  ```json
  {
    "name": "Alex Vance (Lead SecOps)"
  }
  ```

### `POST /api/auth/change-password`
Changes account password.

- **Auth Required**: Yes (`Bearer <token>`)
- **Request Body**:
  ```json
  {
    "current_password": "OldPassword123",
    "new_password": "NewSecurePassword456"
  }
  ```

---

## 3. Email Analysis Endpoints

### `POST /api/analyze/eml`
Uploads and parses an `.eml` raw MIME email file, running the full multi-tier inspection pipeline.

- **Auth Required**: Optional (anonymous fallback supported for demo evaluation)
- **Content-Type**: `multipart/form-data`
- **Form Data**:
  - `file`: Raw `.eml` binary file (Max 20MB)
- **Response `200 OK`**: Returns full `AnalysisReport` object:
  - `report_id`: Unique UUID
  - `email_metadata`: Sender, recipients, subject, date, message-id
  - `findings`:
    - `pii_findings`: Detected emails, phones, Aadhaar, PAN, SSN, tokens (all redacted in evidence)
    - `phishing_findings`: Typosquatting, mismatching reply-to, urgency cues
    - `url_findings`: Shorteners, punycode, IP-based hosts
    - `tracking_findings`: 1x1 pixels, hidden beacons, UTM identifiers
    - `header_findings`: SPF/DKIM/DMARC evaluation
    - `attachment_findings`: Dangerous/double extensions, macro-enabled files
  - `risk_assessment`:
    - `overall_score`: Integer 0–100
    - `risk_category`: `Low` | `Moderate` | `High` | `Very High` | `Critical`
    - `score_breakdown`: Category weights and contributions
    - `recommended_actions`: Concrete remediation advice
  - `ai_assessment`: Local Ollama LLM summary, threat reasoning, and guidance

### `POST /api/analyze/raw`
Submits raw text email contents for quick inspection.

- **Auth Required**: Optional
- **Request Body**:
  ```json
  {
    "raw_email": "From: security@paypal.com\nSubject: Account Verification Required\n..."
  }
  ```

### `GET /api/analyze/samples`
Fetches pre-configured synthetic cybersecurity test emails (phishing, PII leaks, tracking pixels, attachment risks, clean baseline).

---

## 4. Reports Archive Endpoints

### `GET /api/reports`
Lists historical email security analysis reports with filtering and pagination.

- **Auth Required**: Optional
- **Query Parameters**:
  - `risk_level`: `Low` | `Moderate` | `High` | `Very High` | `Critical` (optional)
  - `search`: Search string matching subject or sender
  - `skip`: Integer pagination offset (default 0)
  - `limit`: Integer count (default 20, max 100)
- **Response `200 OK`**:
  ```json
  {
    "total": 5,
    "skip": 0,
    "limit": 20,
    "reports": [...]
  }
  ```

### `GET /api/reports/{report_id}`
Retrieves a complete analysis report by its unique ID.

### `DELETE /api/reports/{report_id}`
Deletes an analysis report from the archive (user-isolated).

### `GET /api/reports/{report_id}/json`
Downloads formatted JSON security artifact with `Content-Disposition: attachment`.

---

## 5. Gmail Integration Endpoints

### `GET /api/gmail/status`
Checks if the current operator has an active Google OAuth Gmail connection.

### `GET /api/gmail/auth-url`
Generates a secure Google OAuth 2.0 authorization URL with CSRF state protection requesting read-only Gmail access (`https://www.googleapis.com/auth/gmail.readonly`).

### `GET /api/gmail/callback`
Receives authorization `code` and `state`, verifies CSRF token, exchanges code for refresh token, and encrypts token server-side using Fernet.

### `GET /api/gmail/messages`
Retrieves message headers and snippet summaries from the connected Gmail inbox.

### `POST /api/gmail/analyze`
Downloads and analyzes user-selected Gmail messages by message ID.

- **Request Body**:
  ```json
  {
    "message_ids": ["18f2d5e712a4b89c"]
  }
  ```

### `DELETE /api/gmail/disconnect`
Revokes Google OAuth credentials and deletes encrypted tokens from the database.

---

## 6. Dashboard & Threat Intelligence Endpoints

### `GET /api/dashboard/stats`
Aggregates key metrics: total emails scanned, high-risk count, critical findings, PII leaks, phishing attempts, tracking pixels, risk distribution chart data, and live threat alerts.

### `GET /api/threat-intel`
Provides catalog of known tracking networks, suspicious TLDs, and recent threat patterns.

### `POST /api/threat-intel/inspect-url`
Standalone inspection of any URL for homograph attacks, punycode, IP-based destinations, and reputation indicators.

---

## 7. User Settings Endpoints

### `GET /api/settings`
Returns current user's security configuration (AI toggle, Ollama model, retention days, PII masking, notifications).

### `PUT /api/settings`
Updates security preferences and retention limits.
