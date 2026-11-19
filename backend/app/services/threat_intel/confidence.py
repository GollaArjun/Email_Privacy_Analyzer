from typing import Dict, Any, Tuple

CONFIDENCE_TIERS = {
    "Confirmed": {
        "score_range": (90, 100),
        "description": "Supported by official vendor disclosure, regulatory SEC filing, or authoritative evidence.",
        "color": "#10B981"  # Emerald
    },
    "Corroborated": {
        "score_range": (75, 89),
        "description": "Supported by multiple independent credible threat intelligence or journalism sources.",
        "color": "#06B6D4"  # Cyan
    },
    "Reported": {
        "score_range": (50, 74),
        "description": "Supported by a credible security research publication but awaiting independent verification.",
        "color": "#3B82F6"  # Blue
    },
    "Unverified": {
        "score_range": (10, 49),
        "description": "Based on unverified threat-actor claims, dark-web advertisements, or preliminary forum listings.",
        "color": "#F59E0B"  # Amber
    }
}

class ConfidenceEvaluator:
    """Evaluates and assigns confidence levels and scores to cybersecurity intelligence."""

    @staticmethod
    def evaluate(
        source_name: str,
        category: str,
        has_official_statement: bool = False,
        source_count: int = 1,
        is_darkweb_claim: bool = False
    ) -> Tuple[str, int]:
        """Determine verification status tier ('Confirmed', 'Corroborated', 'Reported', 'Unverified') and numeric score."""
        if is_darkweb_claim or category == "Unverified Threat-Actor Claim":
            return "Unverified", 40

        if has_official_statement or any(auth in source_name.lower() for auth in ["cisa", "cert-in", "microsoft", "google", "sec 8-k", "have i been pwned"]):
            return "Confirmed", 98

        if source_count >= 2:
            return "Corroborated", 82

        return "Reported", 65
