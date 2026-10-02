"""
MITRE ATT&CK Mapping Utilities.
"""

ATTACK_MAP = {
    "brute force": {
        "id": "T1110",
        "name": "Brute Force"
    },
    "phishing": {
        "id": "T1566",
        "name": "Phishing"
    },
    "port scan": {
        "id": "T1046",
        "name": "Network Service Discovery"
    },
    "credential dumping": {
        "id": "T1003",
        "name": "OS Credential Dumping"
    },
    "risky service exposure": {
        "id": "T1021",
        "name": "Remote Services"
    }
}

def map_attack_type(attack_type: str) -> dict:
    """Returns the MITRE mapping for a given attack type."""
    if not attack_type:
        return {"id": "Unknown", "name": "Unknown"}
        
    attack_lower = attack_type.lower()
    for key, value in ATTACK_MAP.items():
        if key in attack_lower:
            return value
    return {"id": "Unknown", "name": attack_type}

def get_attack_name(attack_type: str) -> str:
    """Returns the MITRE name for a given attack type."""
    return map_attack_type(attack_type).get("name", attack_type)

def get_attack_category(attack_type: str) -> str:
    """Returns the MITRE ID for a given attack type."""
    return map_attack_type(attack_type).get("id", "Unknown")
