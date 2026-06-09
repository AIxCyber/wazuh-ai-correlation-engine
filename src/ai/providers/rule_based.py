
from typing import Any

from src.ai.providers.base import AIProvider
from src.normalization.schema import AIAnalysisResponse


class RuleBasedProvider(AIProvider):
    def name(self) -> str:
        return "rule"

    def analyze(self, incident: dict[str, Any]) -> AIAnalysisResponse:
        event_types = incident.get("event_types") or []
        affected_hosts = incident.get("affected_hosts") or []
        source_ips = incident.get("source_ips") or []
        host_count = len(affected_hosts)
        ip_count = len(source_ips)
        alert_count = incident.get("alert_count") or 0
        severity = incident.get("severity") or "medium"

        root_cause = self._generate_root_cause(event_types, alert_count, host_count, ip_count)
        summary = self._generate_summary(event_types, alert_count, host_count, ip_count)
        actions = self._generate_actions(event_types, severity)
        techniques = incident.get("mitre_technique_id") or "T1078"
        if isinstance(techniques, str):
            techniques = [techniques]

        return AIAnalysisResponse(
            root_cause=root_cause,
            confidence=0.75,
            summary=summary,
            recommended_actions=actions,
            mitre_techniques=techniques,
            severity=severity,
        )

    def summarize_alerts(self, alerts: list[dict[str, Any]]) -> str:
        if not alerts:
            return "No alerts to summarize."
        types = set(a.get("event_type", "unknown") for a in alerts)
        hosts = set(a.get("host", "unknown") for a in alerts)
        return (
            f"{len(alerts)} alerts detected: {', '.join(sorted(types))} "
            f"affecting {len(hosts)} host(s)."
        )

    def _generate_root_cause(
        self, event_types: list[str], alert_count: int, host_count: int, ip_count: int
    ) -> str:
        if "brute_force" in event_types:
            return (
                f"Likely brute-force attack detected with {alert_count} "
                f"attempts from {ip_count} source(s) targeting {host_count} host(s)."
            )
        if "malware" in event_types:
            return (
                f"Possible malware infection detected across {host_count} host(s) "
                f"with {alert_count} associated alerts."
            )
        if "privilege_escalation" in event_types:
            return (
                f"Privilege escalation attempt detected on {host_count} host(s) "
                f"involving {alert_count} alerts."
            )
        if "lateral_movement" in event_types:
            return (
                f"Lateral movement detected from {ip_count} source(s) "
                f"to {host_count} host(s) with {alert_count} alerts."
            )
        return (
            f"Suspicious activity detected: {alert_count} alert(s) "
            f"of type {', '.join(event_types) if event_types else 'unknown'}."
        )

    def _generate_summary(
        self, event_types: list[str], alert_count: int, host_count: int, ip_count: int
    ) -> str:
        type_str = ", ".join(event_types) if event_types else "unknown activity"
        return (
            f"{alert_count} alert(s) of type '{type_str}' detected "
            f"from {ip_count} IP(s) affecting {host_count} host(s). "
            f"Immediate investigation recommended."
        )

    def _generate_actions(self, event_types: list[str], severity: str) -> list[str]:
        actions = []
        if "brute_force" in event_types:
            actions.extend([
                "Block source IPs at perimeter firewall",
                "Reset credentials for affected accounts",
                "Enable rate limiting on authentication services",
                "Review authentication logs for successful logins",
            ])
        if "malware" in event_types:
            actions.extend([
                "Isolate affected hosts immediately",
                "Run full antivirus/EDR scan on affected systems",
                "Check for data exfiltration indicators",
                "Review network connections from affected hosts",
            ])
        if "privilege_escalation" in event_types:
            actions.extend([
                "Review user account permissions",
                "Audit recent privilege changes",
                "Disable compromised accounts",
                "Implement principle of least privilege",
            ])
        if "lateral_movement" in event_types:
            actions.extend([
                "Segment affected network segments",
                "Review remote access logs",
                "Check for backdoor creation",
                "Rotate all credentials on affected systems",
            ])
        if not actions:
            actions = [
                "Review incident details in dashboard",
                "Correlate with other security tools",
                "Document findings in incident report",
                "Escalate if severity is high or critical",
            ]
        if severity in ("high", "critical"):
            actions.insert(0, "ESCALATE IMMEDIATELY to senior analyst team")

        return actions
