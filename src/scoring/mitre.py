
from typing import Any

from src.core.logging import get_logger

logger = get_logger(__name__)

MITRE_MAPPING: dict[str, dict[str, str]] = {
    "authentication": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
    },
    "malware": {
        "technique_id": "T1204",
        "technique": "User Execution",
        "tactic": "Execution",
    },
    "privilege_escalation": {
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique": "Remote Services",
        "tactic": "Lateral Movement",
    },
    "persistence": {
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "tactic": "Persistence",
    },
    "exfiltration": {
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "discovery": {
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "tactic": "Discovery",
    },
    "collection": {
        "technique_id": "T1005",
        "technique": "Data from Local System",
        "tactic": "Collection",
    },
    "command_and_control": {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command And Control",
    },
}

TECHNIQUE_BY_RULE_ID: dict[str, str] = {
    "5710": "brute_force",
    "5715": "brute_force",
    "5720": "brute_force",
    "550": "malware",
    "510": "malware",
    "31100": "malware",
    "31101": "malware",
    "806": "privilege_escalation",
    "807": "privilege_escalation",
    "1100": "lateral_movement",
    "2100": "lateral_movement",
    "5100": "persistence",
    "5200": "exfiltration",
    "5300": "discovery",
}


class MitreMapper:
    def map_event_type(self, event_type: str) -> dict[str, str]:
        return MITRE_MAPPING.get(event_type, {
            "technique_id": "T1078",
            "technique": "Valid Accounts",
            "tactic": "Defense Evasion",
        })

    def map_rule_id(self, rule_id: str) -> dict[str, str] | None:
        event_type = TECHNIQUE_BY_RULE_ID.get(rule_id)
        if event_type:
            return MITRE_MAPPING.get(event_type)
        return None

    def map_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        event_types = incident.get("event_types", [])

        if not event_types:
            for alert in incident.get("alerts", []):
                et = alert.get("event_type") if isinstance(alert, dict) else getattr(alert, "event_type", None)
                if et and et not in event_types:
                    event_types.append(et)

        techniques = []
        for et in event_types:
            mapping = self.map_event_type(et)
            if mapping not in techniques:
                techniques.append(mapping)

        incident["mitre_mapping"] = techniques
        if techniques:
            incident["mitre_technique_id"] = techniques[0]["technique_id"]
            incident["mitre_technique"] = techniques[0]["technique"]
            incident["mitre_tactic"] = techniques[0]["tactic"]

        return incident
