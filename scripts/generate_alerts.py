"""Generate sample Wazuh alert JSON files for ingestion testing."""
import json
import os
import uuid
from datetime import UTC, datetime, timedelta

OUTPUT_DIR = "data/alerts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

now = datetime.now(UTC)

sample_alerts = [
    {
        "timestamp": (now - timedelta(minutes=5)).isoformat(),
        "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force Attempt", "groups": ["ssh", "authentication"]},
        "agent": {"name": "web-01", "id": "001"},
        "data": {"srcip": "203.0.113.5", "dstip": "192.168.1.10", "user": "root", "hostname": "web-01"},
        "location": "/var/log/auth.log",
        "id": str(uuid.uuid4()),
    },
    {
        "timestamp": (now - timedelta(minutes=3)).isoformat(),
        "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force Attempt", "groups": ["ssh", "authentication"]},
        "agent": {"name": "web-01", "id": "001"},
        "data": {"srcip": "203.0.113.5", "dstip": "192.168.1.10", "user": "root", "hostname": "web-01"},
        "location": "/var/log/auth.log",
        "id": str(uuid.uuid4()),
    },
    {
        "timestamp": (now - timedelta(minutes=2)).isoformat(),
        "rule": {"id": "550", "level": 12, "description": "Malware Detected - Trojan", "groups": ["malware", "virus"]},
        "agent": {"name": "db-01", "id": "002"},
        "data": {"srcip": "198.51.100.20", "hostname": "db-01", "file": "/tmp/malicious.exe"},
        "location": "/var/log/syslog",
        "id": str(uuid.uuid4()),
    },
    {
        "timestamp": (now - timedelta(minutes=1)).isoformat(),
        "rule": {"id": "806", "level": 8, "description": "Privilege Escalation Attempt", "groups": ["privilege", "escalation"]},
        "agent": {"name": "mail-01", "id": "003"},
        "data": {"srcip": "192.0.2.10", "dstip": "192.168.1.20", "user": "admin", "hostname": "mail-01"},
        "location": "/var/log/auth.log",
        "id": str(uuid.uuid4()),
    },
    {
        "timestamp": (now - timedelta(minutes=0)).isoformat(),
        "rule": {"id": "1100", "level": 9, "description": "Lateral Movement Detected", "groups": ["lateral", "remote"]},
        "agent": {"name": "web-01", "id": "001"},
        "data": {"srcip": "203.0.113.50", "dstip": "192.168.1.30", "user": "svc_account", "hostname": "web-01"},
        "location": "/var/log/syslog",
        "id": str(uuid.uuid4()),
    },
]

filepath = os.path.join(OUTPUT_DIR, "sample_alerts.json")
with open(filepath, "w") as f:
    json.dump(sample_alerts, f, indent=2)

print(f"Generated {len(sample_alerts)} sample alerts at {filepath}")

# Also generate a malformed alert for DLQ testing
malformed = {"bad": "data", "no_timestamp": True, "rule": "not_a_dict"}
filepath2 = os.path.join(OUTPUT_DIR, "malformed_alert.json")
with open(filepath2, "w") as f:
    json.dump(malformed, f, indent=2)

print(f"Generated malformed alert at {filepath2}")
