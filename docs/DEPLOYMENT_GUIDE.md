# Email Privacy Analyzer (EPA) — Production Deployment Guide

This guide covers deployment procedures for hosting the Email Privacy Analyzer across **Netlify** (Frontend), **Render** (Backend API), and **MongoDB Atlas** (Database).

---

## 1. Architecture Topology

```
+-------------------------------------------------------------+
|                     USER WEB BROWSER                        |
+-------------------------------------------------------------+
                               |
               HTTPS           |           HTTPS
                 +-------------+-------------+
                 |                           |
                 v                           v
+-----------------------------+ +-----------------------------+
|       NETLIFY FRONTEND      | |        RENDER BACKEND       |
|    (React 19 + Vite SPA)    | |    (FastAPI + Python 3.12)  |
+-----------------------------+ +-----------------------------+
                                             |
                               +-------------+-------------+
                               |                           |
                               v                           v
                +-----------------------------+ +-----------------------------+
                |     MONGODB ATLAS CLOUD     | |      LOCAL / CLOUD OLLAMA   |
                |     (Encrypted DB Cluster)  | |     (Optional LLM Engine)   |
                +-----------------------------+ +-----------------------------+
```

---

## 2. Database Setup (MongoDB Atlas)

1. Sign in to [MongoDB Atlas](https://cloud.mongodb.com/).
2. Create an **M0 Free Tier** cluster (AWS or GCP region nearest to your users).
3. Under **Database Access**, create a database user:
   - Username: `epa_app_user`
   - Password: `<strong-random-password>`
4. Under **Network Access**, add an IP Access List entry:
   - Allow access from anywhere (`0.0.0.0/0`) or specify Render's outbound CIDR blocks.
5. In **Clusters** > **Connect**, copy your SRV Connection String:
   ```
   mongodb+srv://epa_app_user:<password>@cluster0.abcde.mongodb.net/email_privacy_analyzer?retryWrites=true&w=majority
   ```

---

## 3. Backend Deployment (Render)

1. Sign in to [Render](https://render.com/).
2. Click **New +** > **Web Service**.
3. Connect your GitHub repository.
4. Configure service settings:
   - **Name**: `email-privacy-analyzer-api`
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt && python -m spacy download en_core_web_sm
     ```
   - **Start Command**:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Plan**: Free or Starter
5. Add Environment Variables:
   | Key | Value | Description |
   |---|---|---|
   | `ENVIRONMENT` | `production` | Enables production security mode |
   | `SECRET_KEY` | `<generate-with-openssl-rand-hex-32>` | JWT HMAC secret key |
   | `ENCRYPTION_KEY` | `<generate-with-cryptography-Fernet-generate_key>` | OAuth token encryption key |
   | `MONGODB_URI` | `mongodb+srv://...` | MongoDB Atlas connection string |
   | `DATABASE_NAME` | `email_privacy_analyzer` | Production database name |
   | `OLLAMA_HOST` | `http://localhost:11434` or remote Ollama endpoint | AI LLM service URL |
   | `CORS_ORIGINS` | `https://your-app.netlify.app` | Allowed frontend origins |
   | `GOOGLE_CLIENT_ID` | `your-google-oauth-client-id` | Google OAuth Client ID |
   | `GOOGLE_CLIENT_SECRET` | `your-google-oauth-client-secret` | Google OAuth Client Secret |
   | `GOOGLE_REDIRECT_URI` | `https://your-app.netlify.app/gmail/callback` | OAuth redirect URI |

---

## 4. Frontend Deployment (Netlify)

1. Sign in to [Netlify](https://www.netlify.com/).
2. Click **Add new site** > **Import an existing project** > **GitHub**.
3. Select your repository.
4. Configure build settings:
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `frontend/dist`
5. Configure Environment Variables in **Site configuration** > **Environment variables**:
   | Key | Value |
   |---|---|
   | `VITE_API_URL` | `https://email-privacy-analyzer-api.onrender.com` |
6. Ensure client-side SPA routing works properly by creating `frontend/public/_redirects`:
   ```
   /*    /index.html   200
   ```
7. Click **Deploy site**.

---

## 5. Google OAuth 2.0 Credentials (Optional Gmail Integration)

To enable live Gmail reading:
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project: `Email Privacy Analyzer`.
3. Enable the **Gmail API** under **APIs & Services** > **Library**.
4. In **OAuth Consent Screen**, configure:
   - User Type: External
   - Add Scope: `https://www.googleapis.com/auth/gmail.readonly`
   - Add Test Users (your Google email address during development).
5. In **Credentials**, click **Create Credentials** > **OAuth client ID**:
   - Application Type: **Web application**
   - Authorized JavaScript origins: `http://localhost:5173`, `https://your-app.netlify.app`
   - Authorized redirect URIs: `http://localhost:5173/gmail/callback`, `https://your-app.netlify.app/gmail/callback`
6. Copy the Client ID and Client Secret into your backend `.env` or Render environment settings.

---

## 6. Verification Checklist

- [ ] Health check endpoint responds: `curl https://<your-render-url>/api/health`
- [ ] Database mode reports `mongodb-live`
- [ ] Frontend successfully communicates with backend without CORS errors
- [ ] Uploading test `.eml` files from `test_samples/` generates an explainable security report
- [ ] PDF and JSON exports download cleanly
- [ ] Rate limiting functions correctly under rapid requests
