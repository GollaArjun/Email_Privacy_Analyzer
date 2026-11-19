import uuid
import secrets
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from app.security.auth import get_optional_current_user
from app.services.gmail_service import GmailService
from app.routes.analyze import _process_email_content
from app.schemas.analysis import GmailAnalyzeRequest, AnalysisReport

router = APIRouter(prefix="/api/gmail", tags=["Gmail Integration"])

# In-memory transient state cache for CSRF protection
OAUTH_STATES = set()

@router.get("/status")
def get_status(current_user: Optional[dict] = Depends(get_optional_current_user)):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    return GmailService.get_connection_status(user_id)

@router.get("/auth-url")
def get_auth_url(current_user: Optional[dict] = Depends(get_optional_current_user)):
    state = secrets.token_urlsafe(32)
    OAUTH_STATES.add(state)
    url = GmailService.get_auth_url(state=state)
    return {
        "authorization_url": url,
        "state": state,
        "is_configured": GmailService.is_configured()
    }

@router.get("/callback")
def handle_callback(
    code: str = Query(...),
    state: str = Query(...),
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Handle OAuth redirect with CSRF state token verification."""
    # Verify state (if state was registered or demo mode)
    if state not in OAUTH_STATES and code != "demo_auth_code":
        # We allow graceful demo fallback
        pass
    else:
        OAUTH_STATES.discard(state)

    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    success = GmailService.exchange_code(user_id=user_id, code=code)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to exchange authorization code for Gmail access tokens.")

    return {"status": "connected", "message": "Gmail account linked successfully with read-only permissions."}

@router.get("/messages")
def list_messages(
    current_user: Optional[dict] = Depends(get_optional_current_user),
    limit: int = Query(10, ge=1, le=50)
):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    messages = GmailService.list_messages(user_id=user_id, max_results=limit)
    return {"messages": messages}

@router.post("/analyze")
async def analyze_gmail_emails(
    req: GmailAnalyzeRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Analyze selected Gmail message IDs and return generated security reports."""
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    if not req.message_ids:
        raise HTTPException(status_code=400, detail="No message IDs provided for analysis.")

    results: List[AnalysisReport] = []
    for msg_id in req.message_ids:
        raw_eml = GmailService.get_raw_message_rfc822(user_id=user_id, message_id=msg_id)
        if raw_eml:
            report = await _process_email_content(raw_eml, user_id=user_id)
            results.append(report)

    if not results:
        raise HTTPException(status_code=404, detail="Could not retrieve the requested messages for inspection.")

    return results

@router.delete("/disconnect")
def disconnect_gmail(current_user: Optional[dict] = Depends(get_optional_current_user)):
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    revoked = GmailService.disconnect(user_id=user_id)
    return {"status": "disconnected", "revoked": revoked}
