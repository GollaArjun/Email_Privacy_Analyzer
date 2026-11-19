import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.threat_intel.base import BaseThreatSource
from app.services.threat_intel.source_manager import threat_manager
from app.services.threat_intel.cisa_kev import CISAKEVSource
from app.services.threat_intel.openphish import OpenPhishSource
from app.services.threat_intel.certin import CERTInSource
from app.services.threat_intel.incident_monitor import VERIFIED_REAL_WORLD_INCIDENTS, IncidentMonitorSource
from app.services.threat_intel.normalizer import ThreatIntelNormalizer
from app.services.threat_intel.confidence import ConfidenceEvaluator
from app.services.threat_intel.deduplicator import IncidentDeduplicator

client = TestClient(app)

def test_source_classes_initialization():
    """Verify threat intelligence sources initialize with valid metadata."""
    cisa = CISAKEVSource()
    assert cisa.source_id == "cisa_kev"
    assert cisa.category == "Vulnerability Intelligence"
    assert not cisa.requires_api_key

    openphish = OpenPhishSource()
    assert openphish.source_id == "openphish"
    assert openphish.category == "Phishing and Malicious URL Intelligence"

    inc_monitor = IncidentMonitorSource()
    assert inc_monitor.source_id == "incident_monitor"

    cert_in = CERTInSource()
    assert cert_in.source_id == "cert_in"
    assert cert_in.category == "Indian Cybersecurity Intelligence"

def test_incident_classification_rules():
    """Verify strict categorization of real-world events per objective rules."""
    ms_outage = next((i for i in VERIFIED_REAL_WORLD_INCIDENTS if "OUTLOOK" in i["incident_id"]), None)
    assert ms_outage is not None
    # Microsoft Outlook outage MUST be classified as Service Outage, not Cyberattack
    assert ms_outage["category"] == "Service Outage"
    assert ms_outage["verification_status"] == "Confirmed"

    zoomcar = next((i for i in VERIFIED_REAL_WORLD_INCIDENTS if "ZOOMCAR" in i["incident_id"]), None)
    assert zoomcar is not None
    # Zoomcar must be classified as Data Breach
    assert zoomcar["category"] == "Data Breach"
    assert "Driving License" in zoomcar["title"] or "Data Exposure" in zoomcar["title"]

    darkweb_claim = next((i for i in VERIFIED_REAL_WORLD_INCIDENTS if "DARKWEB" in i["incident_id"]), None)
    assert darkweb_claim is not None
    # Darkweb claims must be strictly labeled Unverified Threat-Actor Claim
    assert darkweb_claim["category"] == "Unverified Threat-Actor Claim"
    assert darkweb_claim["verification_status"] == "Unverified"
    assert darkweb_claim["confidence_score"] < 50

def test_normalizer_categories_and_cves():
    """Verify ThreatIntelNormalizer classifies text accurately across the 10 mandated categories."""
    # Outage rule
    cat_outage = ThreatIntelNormalizer.classify_incident(
        "Microsoft 365 Exchange Online Service Outage",
        "Elevated error rates and gateway timeouts due to internal BGP routing misconfiguration."
    )
    assert cat_outage == "Service Outage"

    # Darkweb claim rule
    cat_darkweb = ThreatIntelNormalizer.classify_incident(
        "Actor Advertises Alleged Telecom Database on Dark Web Forum",
        "Threat actor claims sale of unconfirmed customer records on BreachForums."
    )
    assert cat_darkweb == "Unverified Threat-Actor Claim"

    # Ransomware rule
    cat_ransomware = ThreatIntelNormalizer.classify_incident(
        "Healthcare Network Paralyzed by LockBit 3.0",
        "Ransomware gang encrypted virtual machine hosts and demands extortion payment."
    )
    assert cat_ransomware == "Ransomware"

    # CVE extraction
    cves = ThreatIntelNormalizer.extract_cves("Advisory addresses CVE-2024-10041 and critical CVE-2024-10042 in Chromium engine.")
    assert "CVE-2024-10041" in cves
    assert "CVE-2024-10042" in cves

def test_confidence_tiers_evaluation():
    """Verify 4-tier confidence system: Confirmed, Corroborated, Reported, Unverified."""
    tier_conf, score_conf = ConfidenceEvaluator.evaluate(
        source_name="CISA Official Advisory", category="Vulnerability Disclosure", has_official_statement=True
    )
    assert tier_conf == "Confirmed"
    assert score_conf >= 90

    tier_unver, score_unver = ConfidenceEvaluator.evaluate(
        source_name="BreachForums", category="Unverified Threat-Actor Claim", is_darkweb_claim=True
    )
    assert tier_unver == "Unverified"
    assert score_unver < 50

    tier_corrob, score_corrob = ConfidenceEvaluator.evaluate(
        source_name="CyberSecurity News", category="Cyberattack", source_count=2
    )
    assert tier_corrob == "Corroborated"
    assert 75 <= score_corrob <= 89

def test_incident_deduplicator_merging():
    """Verify duplicate incident detection by company/date or shared CVEs."""
    inc1 = {
        "incident_id": "INC-001",
        "company": "Acme Cloud Corp",
        "category": "Data Breach",
        "date_reported": "2024-10-15",
        "cve_identifiers": ["CVE-2024-5555"],
        "iocs": ["198.51.100.1"],
        "verification_status": "Reported"
    }
    inc2 = {
        "incident_id": "INC-002",
        "company": "Acme Cloud Corp",
        "category": "Data Breach",
        "date_reported": "2024-10-16",
        "cve_identifiers": ["CVE-2024-5555", "CVE-2024-6666"],
        "iocs": ["198.51.100.2"],
        "verification_status": "Reported"
    }
    assert IncidentDeduplicator.are_duplicates(inc1, inc2)

    merged = IncidentDeduplicator.merge_incidents(inc1, inc2)
    assert "CVE-2024-6666" in merged["cve_identifiers"]
    assert "198.51.100.2" in merged["iocs"]
    assert merged["verification_status"] == "Corroborated"

def test_threat_manager_sync_execution():
    """Execute live synchronization and check data ingestion across all sources including CERT-In."""
    res = threat_manager.sync_all()
    assert res["status"] == "success"
    assert res["total_items"] > 0
    assert "cisa_kev" in res["results"]
    assert "openphish" in res["results"]
    assert "incident_monitor" in res["results"]
    assert "cert_in" in res["results"]

def test_threats_api_endpoints():
    """Test all Phase 2 and Phase 5 REST API endpoints and filters."""
    # 1. Sources status
    res = client.get("/api/threats/sources")
    assert res.status_code == 200
    sources = res.json().get("sources", [])
    assert len(sources) >= 4  # cisa_kev, openphish, incident_monitor, cert_in

    # 2. Sync status
    res = client.get("/api/threats/sync-status")
    assert res.status_code == 200
    assert "sources_count" in res.json()
    assert res.json()["sources_count"] >= 4

    # 3. List threats & filter by India
    res = client.get("/api/threats?country=India")
    assert res.status_code == 200
    india_incidents = res.json().get("incidents", [])
    assert len(india_incidents) > 0
    assert any(i["country"] == "India" for i in india_incidents)

    # 4. Filter by category: Service Outage
    res_outage = client.get("/api/threats?category=Service%20Outage")
    assert res_outage.status_code == 200
    outage_items = res_outage.json().get("incidents", [])
    assert any(o["category"] == "Service Outage" for o in outage_items)

    # 5. Filter by category: Unverified Threat-Actor Claim
    res_darkweb = client.get("/api/threats?category=Unverified%20Threat-Actor%20Claim")
    assert res_darkweb.status_code == 200
    claim_items = res_darkweb.json().get("incidents", [])
    assert any(c["category"] == "Unverified Threat-Actor Claim" for c in claim_items)

    # 6. Statistics
    res = client.get("/api/threats/statistics")
    assert res.status_code == 200
    stats = res.json()
    assert stats["total_incidents"] > 0
    assert len(stats["categories"]) > 0
    assert stats["total_exploited_vulnerabilities"] > 0
    assert stats["total_threat_indicators"] > 0

    # 7. Vulnerabilities (CISA KEV)
    res = client.get("/api/vulnerabilities?limit=10")
    assert res.status_code == 200
    vulns = res.json().get("vulnerabilities", [])
    assert len(vulns) > 0
    assert "cve_id" in vulns[0]

    # 8. Phishing intelligence (OpenPhish)
    res = client.get("/api/phishing-intelligence?limit=10")
    assert res.status_code == 200
    indicators = res.json().get("indicators", [])
    assert len(indicators) > 0
    assert "indicator_value" in indicators[0]

def test_ssrf_mitigation_safety():
    """Verify SSRF protection blocks loopback, cloud metadata, and RFC1918 private IPs."""
    # Forbidden private / loopback / metadata URLs
    assert not BaseThreatSource.is_safe_external_url("http://localhost:8000/internal")
    assert not BaseThreatSource.is_safe_external_url("http://127.0.0.1/admin")
    assert not BaseThreatSource.is_safe_external_url("http://169.254.169.254/latest/meta-data/")
    assert not BaseThreatSource.is_safe_external_url("http://10.0.0.1/secrets")
    assert not BaseThreatSource.is_safe_external_url("http://192.168.1.1/router")
    assert not BaseThreatSource.is_safe_external_url("http://metadata.google.internal")
    assert not BaseThreatSource.is_safe_external_url("file:///etc/passwd")

    # Permitted public feeds
    assert BaseThreatSource.is_safe_external_url("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    assert BaseThreatSource.is_safe_external_url("https://openphish.com/feed.txt")
    assert BaseThreatSource.is_safe_external_url("https://www.google.com/appsstatus/dashboard/incidents.json")

