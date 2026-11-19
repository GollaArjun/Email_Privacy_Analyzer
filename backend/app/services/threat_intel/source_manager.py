import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.services.threat_intel.base import BaseThreatSource
from app.services.threat_intel.cisa_kev import CISAKEVSource
from app.services.threat_intel.openphish import OpenPhishSource
from app.services.threat_intel.incident_monitor import IncidentMonitorSource
from app.services.threat_intel.certin import CERTInSource
from app.database.mongo import (
    get_incidents_col, get_indicators_col, get_vulnerabilities_col,
    get_sources_col, get_sync_logs_col
)

logger = logging.getLogger("epa.threat_intel.manager")

class ThreatIntelligenceManager:
    _instance = None

    def __init__(self):
        self.sources: Dict[str, BaseThreatSource] = {
            "cisa_kev": CISAKEVSource(),
            "openphish": OpenPhishSource(),
            "incident_monitor": IncidentMonitorSource(),
            "cert_in": CERTInSource()
        }
        self.last_full_sync: Optional[str] = None
        self.is_syncing: bool = False

    def sync_all(self, background: bool = False) -> Dict[str, Any]:
        """Trigger synchronization across all registered live intelligence sources."""
        if self.is_syncing:
            return {"status": "already_syncing", "message": "Synchronization is already underway."}

        self.is_syncing = True
        start_time = datetime.now(timezone.utc)
        results: Dict[str, Any] = {}
        total_items = 0

        sources_col = get_sources_col()
        logs_col = get_sync_logs_col()

        try:
            for s_id, source in self.sources.items():
                logger.info(f"Synchronizing intelligence source '{s_id}'...")
                try:
                    res = source.fetch_and_sync()
                    results[s_id] = res
                    total_items += res.get("new", 0) + res.get("updated", 0)
                except Exception as src_err:
                    logger.error(f"Error syncing source {s_id}: {src_err}")
                    results[s_id] = {"success": False, "error": str(src_err)}

                # Persist source metadata and health
                try:
                    sources_col.update_one(
                        {"source_id": s_id},
                        {"$set": source.to_source_metadata()},
                        upsert=True
                    )
                except Exception as meta_err:
                    logger.warning(f"Could not persist metadata for {s_id}: {meta_err}")

            end_time = datetime.now(timezone.utc)
            duration_sec = round((end_time - start_time).total_seconds(), 2)
            self.last_full_sync = end_time.isoformat()

            # Record audit log
            sync_log = {
                "log_id": str(uuid.uuid4()),
                "timestamp": self.last_full_sync,
                "duration_seconds": duration_sec,
                "sources_polled": list(self.sources.keys()),
                "total_items_processed": total_items,
                "results": results
            }
            logs_col.insert_one(sync_log)

            logger.info(f"Full threat intelligence synchronization completed in {duration_sec}s.")
            return {
                "status": "success",
                "timestamp": self.last_full_sync,
                "duration_seconds": duration_sec,
                "total_items": total_items,
                "results": results
            }

        except Exception as e:
            logger.error(f"Error during threat intelligence sync: {e}")
            return {"status": "error", "error": str(e)}
        finally:
            self.is_syncing = False

    def get_sources_status(self) -> List[Dict[str, Any]]:
        """Retrieve telemetry and operational health for all registered sources."""
        sources_col = get_sources_col()
        records = list(sources_col.find({}, {"_id": 0}))

        if not records:
            # Return current in-memory metadata if DB not yet synced
            return [s.to_source_metadata() for s in self.sources.values()]
        return records

    def get_incidents(
        self,
        category: Optional[str] = None,
        country: Optional[str] = None,
        sector: Optional[str] = None,
        confidence: Optional[str] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Query real cyber incidents with multi-dimensional filtering."""
        col = get_incidents_col()
        query: Dict[str, Any] = {}

        if category and category.lower() != "all":
            query["category"] = {"$regex": f"^{category}$", "$options": "i"}

        if country and country.lower() != "all":
            query["country"] = {"$regex": f"^{country}$", "$options": "i"}

        if sector and sector.lower() != "all":
            query["affected_sector"] = {"$regex": sector, "$options": "i"}

        if confidence and confidence.lower() != "all":
            query["verification_status"] = {"$regex": f"^{confidence}$", "$options": "i"}

        if search and search.strip():
            s = search.strip()
            query["$or"] = [
                {"title": {"$regex": s, "$options": "i"}},
                {"company": {"$regex": s, "$options": "i"}},
                {"description": {"$regex": s, "$options": "i"}},
                {"incident_id": {"$regex": s, "$options": "i"}}
            ]

        total = col.count_documents(query)
        items = list(col.find(query, {"_id": 0}).sort("date_reported", -1).skip(skip).limit(limit))

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "incidents": items
        }

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a specific incident by unique incident ID."""
        col = get_incidents_col()
        return col.find_one({"incident_id": incident_id}, {"_id": 0})

    def get_statistics(self) -> Dict[str, Any]:
        """Aggregate statistical metrics strictly from real ingested records."""
        inc_col = get_incidents_col()
        ind_col = get_indicators_col()
        vuln_col = get_vulnerabilities_col()

        incidents = list(inc_col.find({}, {"_id": 0}))

        # Category breakdown
        category_counts: Dict[str, int] = {}
        country_counts: Dict[str, int] = {}
        sector_counts: Dict[str, int] = {}
        confidence_counts: Dict[str, int] = {}

        for inc in incidents:
            cat = inc.get("category", "Uncategorized")
            category_counts[cat] = category_counts.get(cat, 0) + 1

            cntry = inc.get("country", "Unknown")
            country_counts[cntry] = country_counts.get(cntry, 0) + 1

            sec = inc.get("affected_sector", "Other")
            sector_counts[sec] = sector_counts.get(sec, 0) + 1

            conf = inc.get("verification_status", "Unverified")
            confidence_counts[conf] = confidence_counts.get(conf, 0) + 1

        total_indicators = ind_col.count_documents({})
        total_vulns = vuln_col.count_documents({})

        return {
            "total_incidents": len(incidents),
            "total_threat_indicators": total_indicators,
            "total_exploited_vulnerabilities": total_vulns,
            "last_synchronization": self.last_full_sync,
            "categories": [{"name": k, "count": v} for k, v in category_counts.items()],
            "countries": [{"name": k, "count": v} for k, v in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
            "sectors": [{"name": k, "count": v} for k, v in sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
            "confidence_distribution": [{"name": k, "count": v} for k, v in confidence_counts.items()],
            "sources_online": len([s for s in self.sources.values() if s.last_status == "healthy"])
        }

    def get_vulnerabilities(self, search: Optional[str] = None, skip: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Query CISA KEV actively exploited vulnerabilities."""
        col = get_vulnerabilities_col()
        query: Dict[str, Any] = {}

        if search and search.strip():
            s = search.strip()
            query["$or"] = [
                {"cve_id": {"$regex": s, "$options": "i"}},
                {"vendor_project": {"$regex": s, "$options": "i"}},
                {"product": {"$regex": s, "$options": "i"}},
                {"short_description": {"$regex": s, "$options": "i"}}
            ]

        total = col.count_documents(query)
        items = list(col.find(query, {"_id": 0}).sort("date_added", -1).skip(skip).limit(limit))

        return {"total": total, "skip": skip, "limit": limit, "vulnerabilities": items}

    def get_indicators(self, search: Optional[str] = None, skip: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Query active malicious indicators and phishing URLs."""
        col = get_indicators_col()
        query: Dict[str, Any] = {}

        if search and search.strip():
            s = search.strip()
            query["$or"] = [
                {"indicator_value": {"$regex": s, "$options": "i"}},
                {"domain": {"$regex": s, "$options": "i"}}
            ]

        total = col.count_documents(query)
        items = list(col.find(query, {"_id": 0}).sort("last_seen", -1).skip(skip).limit(limit))

        return {"total": total, "skip": skip, "limit": limit, "indicators": items}

threat_manager = ThreatIntelligenceManager()
