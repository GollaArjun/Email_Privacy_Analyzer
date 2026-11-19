# Email Privacy Analyzer & Cyber Threat Intelligence Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_19_%2B_Vite-61DAFB.svg?logo=react)](https://react.dev)
[![TailwindCSS](https://img.shields.io/badge/UI-Tailwind_CSS-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB_%2B_PyMongo-47A248.svg?logo=mongodb)](https://www.mongodb.com)
[![Threat Feeds](https://img.shields.io/badge/Intelligence-CISA_KEV_%2B_OpenPhish_%2B_CERT--In-red.svg)](https://www.cisa.gov)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade cybersecurity, email privacy analysis, and real-time threat intelligence platform. The **Email Security & Threat Intelligence Platform** inspects raw MIME `.eml` communications, detects credential leaks, PII exposures, and phishing tactics, and correlates extracted indicators with live feeds from CISA KEV, OpenPhish, CERT-In, Microsoft 365, Google Workspace, and company breach disclosures.

---

## Key Features

- **Live Cyber Threat Intelligence Feeds**:
  - **CISA Known Exploited Vulnerabilities (KEV)**: Actively exploited CVEs indexed with remediation timelines.
  - **OpenPhish Community Intelligence**: Real-time verified phishing URLs and deceptive domain infrastructure.
  - **CERT-In Indian Cybersecurity Advisories**: Public advisories, targeted mobile banking SMiShing alerts, and Indian breach disclosures.
  - **Company Status & Outage Monitoring**: Live Google Workspace outage JSON feed, Microsoft 365 / Exchange Online status disclosures, Zoom, and Zoomcar security disclosures.
  - **Ethical Breach & Exposure Intelligence**: Corroborates public disclosures (Zoomcar, Snowflake) while treating dark-web forum claims strictly as *Unverified Threat-Actor Claims*.
- **Integrated Email Threat Correlation**:
  - Non-intrusive indicator extraction (URLs, hostnames, attachment SHA-256 hashes).
  - Safe evaluation: Never visits suspicious URLs automatically and never transmits private email bodies to external threat databases.
  - Strict verdict transparency: Displays `"No match found in checked sources"` rather than claiming an email is unconditionally "Safe".
- **Multi-Vector Threat Detection**:
  - **PII Exposure & Credential Leaks**: Detects emails, phone numbers, Aadhaar numbers, PAN cards, SSN, IP addresses, AWS keys, passwords, and GitHub tokens with automatic evidence redaction.
  - **Phishing & Social Engineering**: Identifies typosquatting domains, punycode lookalikes, URL shorteners, IP-based links, deceptive Reply-To/From mismatches, and urgent manipulation language.
  - **Email Tracking Beacons**: Spots invisible 1x1 tracking pixels, hidden zero-dimension images, and telemetry parameters from email service providers (SendGrid, Mailchimp, HubSpot).
  - **Header Security Analysis**: Analyzes SPF, DKIM, and DMARC authentication verdicts, hop count anomalies, and suspicious return paths without making false claims.
  - **Attachment Sandbox Safety**: Flags executables, double extensions (`.pdf.exe`), macro-enabled Office files (`.docm`), and MIME type mismatches without executing code.
- **Explainable Privacy Risk Score**:
  - Transparent 0–100 heuristic scoring model categorized into 5 tiers: **Low (0–19)**, **Moderate (20–39)**, **High (40–59)**, **Very High (60–79)**, and **Critical (80–100)** with threat feed weighting.
- **Automated 15-Minute Background Synchronization Worker**:
  - Background worker continuously synchronizes public feeds every 15 minutes.
  - Automatic stale data indicators and manual on-demand sync button.
- **Hybrid AI Architecture**:
  - Deterministic security analysis paired with local **Ollama** LLM reasoning (treating email content as strictly untrusted data).
  - Works offline or when Ollama is unavailable via built-in heuristic security fallbacks.
- **Gmail OAuth 2.0 Integration**:
  - Connects to Gmail using minimal read-only permissions (`gmail.readonly`).
  - Server-side AES-128 token encryption at rest via Fernet with CSRF state protection.
- **Cybersecurity Operations Dashboard**:
  - Dark theme cyber console built with React 19, Tailwind CSS, Recharts telemetry, and glass-effect panels.
  - 1-Click PDF export (`jspdf` + `html2canvas`) and SIEM-compliant JSON downloads.
  - 1-Click Demo Evaluator Login for instant review without external setup.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   React 19 + Vite Frontend  |
                      |   (Cybersecurity Dashboard) |
                      +--------------+--------------+
                                     |
                                REST API (JWT)
                                     v
                      +-----------------------------+
                      |       FastAPI Backend       |
                      |   (Routing + Rate Limiter)  |
                      +--------------+--------------+
                                     |
    +--------------------------------+--------------------------------+
    |                                |                                |
    v                                v                                v
+-----------------------+  +-----------------------+  +-----------------------+
| Security Engine       |  | Storage Layer         |  | AI & External Auth    |
| - Email MIME Parser   |  | - MongoDB / MongoMock |  | - Ollama Local LLM   |
| - Presidio PII Engine |  | - User Isolation      |  | - Google OAuth 2.0    |
| - Phishing Detector   |  | - Fernet Token Encrypt|  | - Gmail API (Read-only|
| - Tracking Detector   |  | - Automatic Retention |  +-----------------------+
| - Header Inspector    |  +-----------------------+
| - Attachment Analyzer |
| - Heuristic Scorer    |
+-----------------------+
```

---

## Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 19, Vite, Tailwind CSS, Lucide React, Recharts, Axios, jsPDF, html2canvas |
| **Backend** | Python 3.12+, FastAPI, Pydantic v2, Python `email` MIME parser, Uvicorn |
| **Security & NLP** | Microsoft Presidio, spaCy (`en_core_web_sm`), Cryptography (Fernet), PyJWT, bcrypt |
| **Local AI** | Ollama (`llama3`, `mistral`, `gemma`) with heuristic fallback |
| **Database** | MongoDB with PyMongo (automatic fallback to in-memory `mongomock`) |
| **Integrations** | Google OAuth 2.0 with Gmail API (`https://www.googleapis.com/auth/gmail.readonly`) |

---

## Directory Structure

```
Mail_Analyaer/
├── backend/
│   ├── app/
│   │   ├── config.py                  # Pydantic BaseSettings configuration
│   │   ├── main.py                    # FastAPI application & startup lifespan
│   │   ├── database/
│   │   │   └── mongo.py               # MongoDB client with MongoMock fallback
│   │   ├── middleware/
│   │   │   └── rate_limiter.py        # Per-IP rate limiting middleware
│   │   ├── routes/
│   │   │   ├── analyze.py             # EML upload & raw email analysis
│   │   │   ├── auth.py                # Register, login, profile, password change
│   │   │   ├── dashboard.py           # Metrics aggregation & alerts
│   │   │   ├── gmail.py               # OAuth flow, inbox listing, message scanning
│   │   │   ├── reports.py             # Report archive, search, JSON export, delete
│   │   │   └── settings.py            # AI configuration & retention settings
│   │   ├── schemas/
│   │   │   └── analysis.py            # Pydantic data contracts & request models
│   │   ├── security/
│   │   │   ├── auth.py                # JWT creation, decode, FastAPI dependency
│   │   │   └── crypto.py              # bcrypt password hashing & Fernet encryption
│   │   ├── services/
│   │   │   ├── ai_engine.py           # Ollama LLM integration & heuristic fallback
│   │   │   ├── attachment_analyzer.py # Executable, macro, double-extension checks
│   │   │   ├── email_parser.py        # MIME parser for headers, bodies, attachments
│   │   │   ├── gmail_service.py       # Google OAuth exchange & Gmail API wrapper
│   │   │   ├── header_analyzer.py     # SPF, DKIM, DMARC, Reply-To mismatch logic
│   │   │   ├── phishing_detector.py   # Typosquatting, shorteners, punycode links
│   │   │   ├── pii_detector.py        # Presidio + regex PII scanner with masking
│   │   │   ├── scoring_engine.py      # Deduplicated 0-100 risk scoring engine
│   │   │   └── tracking_detector.py   # 1x1 pixels, hidden beacons, UTM parameters
│   │   └── utils/
│   │       └── sample_emails.py       # Synthetic test email seed dataset
│   ├── requirements.txt
│   ├── .env.example
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── components/                # Navbar, Sidebar, ScoreGauge, StatCard, RiskBadge
│   │   ├── context/                   # AuthContext with demo evaluator session
│   │   ├── hooks/                     # useAuth
│   │   ├── layouts/                   # MainLayout with cyber theme
│   │   ├── pages/                     # Dashboard, AnalyzeEmail, Report, Gmail, History, etc.
│   │   └── services/api.js            # Axios client with interceptors
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── tests/                             # Pytest automated test suite (8 test modules)
├── test_samples/                      # Synthetic .eml test files
├── docs/                              # API documentation, DB schema, deployment guide
└── README.md
```

---

## Quick Start (Local Setup)

### 1. Prerequisites
- **Python 3.10+**
- **Node.js 18+** and **npm**
- *(Optional)* [Ollama](https://ollama.ai) running locally for AI inference (`ollama run llama3`)
- *(Optional)* Local MongoDB running on `localhost:27017` (automatic mock fallback if not present)

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy English language model
python -m spacy download en_core_web_sm

# Launch FastAPI development server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend starts at `http://localhost:8000`. You can test it immediately by visiting `http://localhost:8000/api/health`.

### 3. Frontend Setup
```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install npm packages
npm install

# Start Vite dev server
npm run dev
```

The frontend launches at `http://localhost:5173`. Open your browser and explore the app!

---

## Evaluation Mode (Instant 1-Click Demo)

Don't have time to register an account?
1. Open `http://localhost:5173`.
2. On the login screen, click **Instant 1-Click Demo Login (Evaluator Mode)**.
3. You will immediately access the pre-seeded security operations dashboard with pre-analyzed email threats, charts, and sample files.

---

## Testing

The project includes an automated test suite verifying all detection modules, scoring calculations, and API routes:

```bash
# Run all backend unit and integration tests
pytest tests/ -v
```

Test coverage includes:
- `test_parser.py`: MIME parsing, boundary handling, multi-part extraction.
- `test_pii.py`: Aadhaar, PAN, SSN, API key detection and evidence masking.
- `test_phishing.py`: Lookalike domains, shorteners, urgency triggers, Reply-To mismatches.
- `test_tracking.py`: 1x1 zero-dimension tracking pixels and marketing beacons.
- `test_headers.py`: SPF, DKIM, and DMARC verification rules.
- `test_attachments.py`: Malicious executables, double extensions, macro detection.
- `test_scoring.py`: Heuristic 0–100 risk score weighting and deduplication.
- `test_api.py`: FastAPI endpoints, authentication, upload validation, JSON export.

---

## Production Deployment

Refer to the complete deployment guide in [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md):
- **Frontend**: Deployed to **Netlify** (`npm run build`, publish directory `dist`).
- **Backend**: Deployed to **Render** (`uvicorn app.main:app --host 0.0.0.0 --port $PORT`).
- **Database**: Managed cluster on **MongoDB Atlas** with SSL encryption at rest.

---

## Documentation

- [REST API Specification](docs/API_DOCUMENTATION.md)
- [Database Schema & Data Models](docs/DATABASE_SCHEMA.md)
- [Production Deployment Guide](docs/DEPLOYMENT_GUIDE.md)

---

## License

This project is licensed under the MIT License — see the LICENSE file for details.
