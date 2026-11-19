import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Depends
from app.database.mongo import get_users_col, get_reports_col
from app.security.crypto import hash_password, verify_password
from app.security.auth import create_access_token, get_current_user
from app.schemas.analysis import (
    UserRegisterRequest, UserLoginRequest, TokenResponse,
    UserProfileResponse, PasswordChangeRequest, UserUpdateRequest
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
def register_user(req: UserRegisterRequest):
    users_col = get_users_col()
    existing = users_col.find_one({"email": req.email.lower()})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    now_iso = datetime.now(timezone.utc).isoformat()

    user_doc = {
        "user_id": user_id,
        "name": req.name.strip(),
        "email": req.email.lower().strip(),
        "password_hash": pw_hash,
        "created_at": now_iso
    }
    users_col.insert_one(user_doc)

    token = create_access_token({"sub": user_id, "email": req.email.lower()})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user={"user_id": user_id, "name": req.name, "email": req.email.lower()}
    )

@router.post("/login", response_model=TokenResponse)
def login_user(req: UserLoginRequest):
    users_col = get_users_col()
    user = users_col.find_one({"email": req.email.lower().strip()})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = create_access_token({"sub": user["user_id"], "email": user["email"]})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user={"user_id": user["user_id"], "name": user["name"], "email": user["email"]}
    )

@router.get("/me", response_model=UserProfileResponse)
def get_me(user_payload: dict = Depends(get_current_user)):
    user_id = user_payload.get("sub")
    users_col = get_users_col()
    user = users_col.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reports_col = get_reports_col()
    total_scans = reports_col.count_documents({"user_id": user_id})
    high_risk_scans = reports_col.count_documents({
        "user_id": user_id,
        "risk_assessment.risk_category": {"$in": ["High", "Very High", "Critical"]}
    })

    return UserProfileResponse(
        user_id=user["user_id"],
        name=user["name"],
        email=user["email"],
        created_at=user.get("created_at", ""),
        stats={"total_scans": total_scans, "high_risk_scans": high_risk_scans}
    )

@router.put("/me", response_model=UserProfileResponse)
def update_me(req: UserUpdateRequest, user_payload: dict = Depends(get_current_user)):
    user_id = user_payload.get("sub")
    users_col = get_users_col()
    user = users_col.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_name = req.name.strip()
    users_col.update_one({"user_id": user_id}, {"$set": {"name": new_name}})
    user["name"] = new_name

    reports_col = get_reports_col()
    total_scans = reports_col.count_documents({"user_id": user_id})
    high_risk_scans = reports_col.count_documents({
        "user_id": user_id,
        "risk_assessment.risk_category": {"$in": ["High", "Very High", "Critical"]}
    })

    return UserProfileResponse(
        user_id=user["user_id"],
        name=user["name"],
        email=user["email"],
        created_at=user.get("created_at", ""),
        stats={"total_scans": total_scans, "high_risk_scans": high_risk_scans}
    )

@router.post("/change-password")
def change_password(req: PasswordChangeRequest, user_payload: dict = Depends(get_current_user)):
    user_id = user_payload.get("sub")
    users_col = get_users_col()
    user = users_col.find_one({"user_id": user_id})
    if not user or not verify_password(req.current_password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_hash = hash_password(req.new_password)
    users_col.update_one({"user_id": user_id}, {"$set": {"password_hash": new_hash}})
    return {"message": "Password updated successfully"}
