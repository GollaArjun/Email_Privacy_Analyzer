from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Response
from app.security.auth import get_optional_current_user
from app.database.mongo import get_reports_col
from app.schemas.analysis import AnalysisReport

router = APIRouter(prefix="/api/reports", tags=["Security Reports"])

@router.get("")
def list_reports(
    current_user: Optional[dict] = Depends(get_optional_current_user),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (Low, Moderate, High, Very High, Critical)"),
    search: Optional[str] = Query(None, description="Search sender or subject"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100)
):
    """Retrieve historical security analysis reports with filtering and pagination."""
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    reports_col = get_reports_col()

    # User isolation query
    query: Dict[str, Any] = {"user_id": user_id}

    if risk_level and risk_level.lower() != "all":
        query["risk_assessment.risk_category"] = {"$regex": f"^{risk_level}$", "$options": "i"}

    if search and search.strip():
        s = search.strip()
        query["$or"] = [
            {"email_metadata.subject": {"$regex": s, "$options": "i"}},
            {"email_metadata.sender": {"$regex": s, "$options": "i"}},
            {"report_id": {"$regex": s, "$options": "i"}}
        ]

    total = reports_col.count_documents(query)
    cursor = reports_col.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    items = list(cursor)

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "reports": items
    }

@router.get("/{report_id}")
def get_report_by_id(
    report_id: str,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Fetch complete analysis report by unique ID."""
    reports_col = get_reports_col()
    doc = reports_col.find_one({"report_id": report_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis report not found.")

    return doc

@router.delete("/{report_id}")
def delete_report(
    report_id: str,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Delete an analysis report."""
    user_id = current_user.get("sub") if current_user else "anonymous_demo_user"
    reports_col = get_reports_col()

    res = reports_col.delete_one({"report_id": report_id, "user_id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Report not found or unauthorized to delete.")

    return {"message": "Report deleted successfully.", "report_id": report_id}

@router.get("/{report_id}/json")
def export_report_json(
    report_id: str,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    """Export formatted JSON security report for external SIEM or forensic archiving."""
    reports_col = get_reports_col()
    doc = reports_col.find_one({"report_id": report_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis report not found.")

    import json
    json_bytes = json.dumps(doc, indent=2).encode('utf-8')
    filename = f"EPA_Report_{report_id[:8]}.json"
    
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
