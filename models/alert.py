"""Backward-compatible alert model used by the existing security tools."""
from datetime import datetime, timezone
from models.ids import make_id


class Alert:
    """Unified finding model; existing tools may keep using their old constructor."""

    def __init__(self, module, source, severity, attack_type, risk_score, evidence,
                 recommended_action, open_ports=None, confidence=None, rule_id=None,
                 mitre=None, status="NEW", *, alert_id=None, timestamp=None,
                 title=None, explanation="", mitre_techniques=None, mitre_tactics=None,
                 evidence_refs=None, grouping_key=None):
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.module = module
        self.source = source
        self.severity = severity
        self.attack_type = attack_type
        self.risk_score = max(0, min(100, int(risk_score)))
        self.evidence = evidence if isinstance(evidence, list) else ([evidence] if evidence else [])
        self.alert_id = alert_id or make_id("alert", module, source, severity, attack_type, self.evidence)
        self.id = self.alert_id
        self.title = title or attack_type
        self.explanation = explanation
        self.mitre_techniques = list(mitre_techniques or ([mitre] if isinstance(mitre, str) else []))
        self.mitre_tactics = list(mitre_tactics or [])
        self.evidence_refs = list(evidence_refs or [])
        self.grouping_key = grouping_key
        self.recommended_action = recommended_action
        self.open_ports = open_ports if open_ports is not None else []
        self.confidence = confidence
        self.rule_id = rule_id
        self.mitre = mitre
        self.status = status

    def to_dict(self):
        return {
            "alert_id": self.alert_id, "timestamp": self.timestamp,
            "module": self.module, "source": self.source,
            "severity": self.severity, "attack_type": self.attack_type,
            "risk_score": self.risk_score, "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "open_ports": self.open_ports, "confidence": self.confidence,
            "rule_id": self.rule_id, "mitre": self.mitre, "status": self.status,
            "id": self.id, "title": self.title, "explanation": self.explanation,
            "mitre_techniques": self.mitre_techniques, "mitre_tactics": self.mitre_tactics,
            "evidence_refs": self.evidence_refs, "grouping_key": self.grouping_key,
        }
