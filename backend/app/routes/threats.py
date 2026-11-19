from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from app.services.threat_intel.source_manager import threat_manager

router = APIRouter(prefix="/api", tags=["Live Cyber Threat Intelligence"])

@router.get("/threats")
def list_cyber_incidents(
    category: Optional[str] = Query(None, description="Category filter (Service Outage, Ransomware, Data Breach, etc.)"),
    country: Optional[str] = Query(None, description="Country filter"),
    sector: Optional[str] = Query(None, description="Sector filter"),
    confidence: Optional[str] = Query(None, description="Confidence filter (Confirmed, Corroborated, Reported, Unverified)"),
    search: Optional[str] = Query(None, description="Search term for title, company, or description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200)
):
    """Retrieve real cyber incidents with multi-dimensional filtering."""
    return threat_manager.get_incidents(
        category=category,
        country=country,
        sector=sector,
        confidence=confidence,
        search=search,
        skip=skip,
        limit=limit
    )

@router.get("/threats/recent")
def get_recent_incidents(limit: int = Query(10, ge=1, le=50)):
    """Retrieve the latest cyber incidents chronologically."""
    res = threat_manager.get_incidents(skip=0, limit=limit)
    return res.get("incidents", [])

@router.get("/threats/statistics")
def get_threat_statistics():
    """Retrieve aggregate statistics across all real-world threat intelligence collections."""
    return threat_manager.get_statistics()

@router.get("/threats/sources")
def get_threat_sources():
    """Retrieve telemetry and operational health for all registered intelligence feeds."""
    return {
        "sources": threat_manager.get_sources_status()
    }

@router.get("/threats/sync-status")
def get_sync_status():
    """Check synchronization status and last run timestamp."""
    return {
        "is_syncing": threat_manager.is_syncing,
        "last_full_sync": threat_manager.last_full_sync,
        "sources_count": len(threat_manager.sources)
    }

@router.post("/threats/sync")
def trigger_threat_sync(background_tasks: BackgroundTasks):
    """Trigger an immediate live feed synchronization."""
    if threat_manager.is_syncing:
        return {"status": "in_progress", "message": "Synchronization is already active."}
    
    background_tasks.add_task(threat_manager.sync_all)
    return {"status": "initiated", "message": "Threat intelligence synchronization triggered in background."}

@router.get("/threats/{incident_id}")
def get_incident_detail(incident_id: str):
    """Fetch complete details and IOCs for a specific cyber incident."""
    inc = threat_manager.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Cyber incident not found.")
    return inc

@router.get("/vulnerabilities")
def get_exploited_vulnerabilities(
    search: Optional[str] = Query(None, description="Search CVE ID, vendor, or product"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100)
):
    """Retrieve CISA KEV actively exploited vulnerabilities."""
    return threat_manager.get_vulnerabilities(search=search, skip=skip, limit=limit)

@router.get("/phishing-intelligence")
def get_phishing_intelligence(
    search: Optional[str] = Query(None, description="Search domain or URL"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100)
):
    """Retrieve live verified phishing indicators from OpenPhish community feed."""
    return threat_manager.get_indicators(search=search, skip=skip, limit=limit)
