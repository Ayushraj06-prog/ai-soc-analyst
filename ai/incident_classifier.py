"""
Incident Classification module.
"""
from ai.attack_mapper import map_attack_type

CLASSIFICATION_MAP = {
    "T1110": "Credential Access",
    "T1566": "Initial Access",
    "T1046": "Reconnaissance",
    "T1003": "Credential Access",
    "T1021": "Lateral Movement"
}

def classify_incident(attack_type: str) -> dict:
    """
    Classifies an incident based on its attack type.
    """
    mitre_data = map_attack_type(attack_type)
    mitre_id = mitre_data.get("id", "Unknown")
    technique = mitre_data.get("name", "Unknown")
    incident_type = CLASSIFICATION_MAP.get(mitre_id, "Unknown/Unclassified")
    
    return {
        "incident_type": incident_type,
        "mitre_id": mitre_id,
        "technique": technique
    }
