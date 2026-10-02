"""Scenario definitions and deterministic mock investigation provider."""
import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    description: str
    fixture: Path
    expected: dict


class MockInvestigationProvider:
    """Return schema-valid output referencing aliases found in the packet prompt."""

    def generate(self, prompt: str) -> str:
        aliases = sorted(set(re.findall(r"\b[DEIM][1-9][0-9]*\b", prompt)))
        event_alias = next((alias for alias in aliases if alias.startswith("E")), aliases[0] if aliases else "E1")
        detection_alias = next((alias for alias in aliases if alias.startswith("D")), event_alias)
        evidence = [event_alias]
        finding = {"text": "Synthetic scenario activity was observed in the supplied evidence.", "basis": "observed", "confidence": "high", "evidence": evidence}
        return json.dumps({
            "summary": "Synthetic scenario investigation completed.",
            "attack_narrative": "The scenario contains bounded synthetic security activity.",
            "timeline_assessment": "The supplied evidence was reviewed in timestamp order.",
            "key_findings": [finding],
            "supported_claims": [finding],
            "attack_progression": [{"text": "The detection is linked to supplied event evidence.", "basis": "observed", "confidence": "high", "evidence": [detection_alias]}],
            "ioc_assessment": [],
            "mitre_assessment": [],
            "uncertainties": [],
            "recommended_actions": [{"action_type": "review_auth_logs", "action": "Review the linked synthetic evidence.", "priority": "medium", "reason": "Validate the bounded scenario context.", "evidence": evidence}],
            "confidence": "high",
            "limitations": [],
        })
