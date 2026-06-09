
from datetime import UTC

from src.normalization.schema import NormalizedAlert, RawWazuhAlert


def normalize_wazuh_alert(raw: RawWazuhAlert) -> NormalizedAlert:
    rule = raw.rule or {}
    agent = raw.agent or {}
    data = raw.data or {}

    timestamp = _parse_timestamp(raw.timestamp)
    event_type = _determine_event_type(rule, data)
    source_ip = _extract_source_ip(data, raw.predecoder)
    destination_ip = _extract_destination_ip(data)
    user = _extract_user(data, raw.predecoder)

    return NormalizedAlert(
        timestamp=timestamp,
        agent_name=agent.get("name", ""),
        host=agent.get("name", data.get("hostname", "")),
        rule_id=str(rule.get("id", "")),
        rule_level=int(rule.get("level", 0)),
        rule_description=rule.get("description", ""),
        source_ip=source_ip,
        destination_ip=destination_ip,
        user=user,
        event_type=event_type,
        raw_data=raw.model_dump(exclude_none=True),
    )


def _parse_timestamp(ts: str | None) -> str:
    if ts:
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
    from datetime import datetime
    return datetime.now(UTC)


def _determine_event_type(rule: dict, data: dict) -> str:
    description = (rule.get("description") or "").lower()
    groups = rule.get("groups") or []

    if "authentication" in groups or "ssh" in groups:
        return "authentication"
    if "malware" in groups or "virus" in description:
        return "malware"
    if "privilege" in description or "escalation" in description:
        return "privilege_escalation"
    if "lateral" in description or "remote" in groups:
        return "lateral_movement"
    if "brute" in description or "bf" in groups:
        return "brute_force"
    if "persistence" in groups or "persist" in description:
        return "persistence"
    if "exfil" in description or "exfiltration" in groups:
        return "exfiltration"
    if "discovery" in groups or "recon" in description:
        return "discovery"

    return "unknown"


def _extract_source_ip(data: dict, predecoder: dict | None) -> str | None:
    for field in ("srcip", "src_ip", "source_ip", "srcaddress"):
        val = data.get(field) or (predecoder or {}).get(field)
        if val and isinstance(val, str) and _is_valid_ip(val):
            return val
    src = data.get("srcip") or (predecoder or {}).get("srcip")
    return str(src) if src else None


def _extract_destination_ip(data: dict) -> str | None:
    for field in ("dstip", "dst_ip", "dest_ip", "destination_ip", "dstaddress"):
        val = data.get(field)
        if val and isinstance(val, str) and _is_valid_ip(val):
            return val
    return None


def _extract_user(data: dict, predecoder: dict | None) -> str | None:
    for field in ("user", "username", "srcuser", "dstuser"):
        val = data.get(field) or (predecoder or {}).get(field)
        if val:
            return str(val)
    return None


def _is_valid_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
