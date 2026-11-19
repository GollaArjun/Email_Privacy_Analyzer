import re
from typing import Dict, Any, List, Optional
from datetime import datetime

class IncidentDeduplicator:
    """Detects duplicate incident reports across intelligence feeds and merges corroborating sources."""

    @staticmethod
    def are_duplicates(inc1: Dict[str, Any], inc2: Dict[str, Any]) -> bool:
        """Evaluate if two incident records refer to the identical real-world event."""
        # 1. Exact ID match
        if inc1.get("incident_id") and inc1.get("incident_id") == inc2.get("incident_id"):
            return True

        # 2. Shared CVE identifiers
        cves1 = set(inc1.get("cve_identifiers") or [])
        cves2 = set(inc2.get("cve_identifiers") or [])
        if cves1 and cves2 and cves1.intersection(cves2):
            return True

        # 3. Same company and date window within 3 days with similar category
        comp1 = (inc1.get("company") or "").strip().lower()
        comp2 = (inc2.get("company") or "").strip().lower()

        if comp1 and comp2 and (comp1 in comp2 or comp2 in comp1):
            date1 = inc1.get("date_reported") or ""
            date2 = inc2.get("date_reported") or ""
            cat1 = inc1.get("category")
            cat2 = inc2.get("category")

            if date1 and date2 and cat1 == cat2:
                try:
                    d1 = datetime.fromisoformat(date1.split("T")[0])
                    d2 = datetime.fromisoformat(date2.split("T")[0])
                    if abs((d1 - d2).days) <= 3:
                        return True
                except Exception:
                    pass

        return False

    @staticmethod
    def merge_incidents(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
        """Merge a secondary incident report into primary record, upgrading confidence."""
        merged = dict(primary)

        # Merge CVEs
        cves = set(primary.get("cve_identifiers") or [])
        cves.update(secondary.get("cve_identifiers") or [])
        merged["cve_identifiers"] = sorted(list(cves))

        # Merge IOCs
        iocs = set(primary.get("iocs") or [])
        iocs.update(secondary.get("iocs") or [])
        merged["iocs"] = sorted(list(iocs))

        # Upgrade confidence to Corroborated if previously only Reported
        if merged.get("verification_status") == "Reported":
            merged["verification_status"] = "Corroborated"
            merged["confidence_score"] = max(merged.get("confidence_score", 65), 85)

        return merged
