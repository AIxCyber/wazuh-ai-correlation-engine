# Wazuh Integration Guide

This guide covers four ways to feed Wazuh alerts into the AI Correlation Engine, from push-based real-time ingestion to file-based batch import. Additional ingestion sources (Wazuh Indexer, Elasticsearch, Kafka) are also documented.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Wazuh Manager                              │
│                                                                 │
│  ossec.conf integration  ◄── agents send alerts                 │
│  or webhook → POST alerts  →  engine API                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP POST (alerts/ingest)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  AI Correlation Engine                          │
│                                                                 │
│  RawWazuhAlert → NormalizedAlert → Dedup → Correlation          │
│  → Enrichment → Scoring → AI Analysis → Incident                │
└─────────────────────────────────────────────────────────────────┘
```

The engine treats Wazuh as an external upstream system. Wazuh manager pushes or exposes alerts; the engine ingests them via its REST API, built-in source connectors, or file watcher.

---

## Prerequisites

- A running Wazuh manager (4.x) with agents sending events
- The AI Correlation Engine deployed and reachable from the Wazuh manager
- Admin credentials or an API token for the engine

---

## Option 1 — Wazuh Integration (custom-integrator)

Wazuh's built-in integration module sends every alert that matches a minimum rule level to an external URL via HTTP POST.

### 1. Generate an API token

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
```

Save the returned token.

### 2. Configure Wazuh integration

Edit `/var/ossec/etc/ossec.conf` on the Wazuh manager:

```xml
<ossec_config>
  <integration>
    <name>custom-integrator</name>
    <hook_url>http://<ENGINE_HOST>:8000/api/v1/alerts/ingest</hook_url>
    <authorization>Bearer <YOUR_JWT_TOKEN></authorization>
    <level>3</level>
    <alert_format>json</alert_format>
    <group>ssh,authentication,malware</group>
  </integration>
</ossec_config>
```

| Parameter | Description |
|-----------|-------------|
| `name` | Must be `custom-integrator` for custom HTTP integrations |
| `hook_url` | Engine's ingest endpoint |
| `authorization` | `Bearer <token>` |
| `level` | Minimum rule level to forward (3 = low) |
| `alert_format` | Must be `json` |
| `group` | *(optional)* Only forward alerts matching these groups |

### 3. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

**Limitation**: Custom-integrator sends one alert per POST. For high-throughput environments, use the webhook method instead.

---

## Option 2 — Wazuh Webhook (batch)

Wazuh 4.3+ supports batched alert delivery via the webhook integration.

### 1. Configure webhook in ossec.conf

```xml
<ossec_config>
  <integration>
    <name>webhook</name>
    <hook_url>http://<ENGINE_HOST>:8000/api/v1/alerts/ingest</hook_url>
    <authorization>Bearer <YOUR_JWT_TOKEN></authorization>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

Using `<name>webhook</name>` tells Wazuh to batch alerts as a JSON array. The engine's `/api/v1/alerts/ingest` endpoint accepts `list[dict]`.

### 2. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

### 3. Tuning batch behaviour

```ini
# /var/ossec/etc/local_internal_options.conf
integration.webhook.batch_time=5
integration.webhook.max_size=1048576
```

---

## Option 3 — Built-in API Polling

The engine includes a built-in `ingest_from_wazuh_api()` method that polls the Wazuh REST API v2 directly.

### 1. Create a Wazuh API user

On the Wazuh manager:

```bash
curl -u wazuh:wazuh -X POST "https://localhost:55000/security/user" \
  -H "Content-Type: application/json" \
  -d '{"username": "engine-poller", "password": "StrongPassword123!"}' \
  -k
```

### 2. Configure engine environment

Add to the engine's `.env`:

```ini
WAZUH_API_URL=https://<WAZUH_MANAGER>:55000
WAZUH_API_USER=engine-poller
WAZUH_API_PASSWORD=StrongPassword123!
WAZUH_API_VERIFY_SSL=false
```

### 3. Configure alert source

Set `ALERT_SOURCE=wazuh_api` in `.env` or use the ingestion service directly:

```python
from src.ingestion.service import AlertIngestionService
svc = AlertIngestionService()
alerts = svc.ingest_from_wazuh_api()
```

The engine authenticates against the Wazuh API's `/security/user/authenticate` endpoint, obtains a JWT token, and fetches alerts from `/alerts` with configurable batch size and sort order.

---

## Option 4 — File-Based Ingestion (testing / air-gapped)

For testing, development, or air-gapped environments, place Wazuh alert JSON files in the configured alerts directory.

### 1. Configure the engine

```yaml
# config/development.yaml
alert_file_path: data/alerts/
poll_interval_seconds: 30
```

### 2. Place alert files

```bash
cp /path/to/wazuh-alerts/*.json data/alerts/
```

### 3. Generate sample alerts

```bash
python scripts/generate_alerts.py
```

### 4. Trigger immediate ingestion

```python
from src.ingestion.service import AlertIngestionService
svc = AlertIngestionService()
svc.ingest_from_local()
```

---

## Additional Ingestion Sources

### Wazuh Indexer (OpenSearch-compatible)

Configure the engine to pull alerts directly from Wazuh Indexer:

```ini
WAZUH_INDEXER_URL=https://<INDEXER_HOST>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=admin
WAZUH_INDEXER_INDEX=wazuh-alerts-*
```

Usage:

```python
svc.ingest_from_wazuh_indexer()
```

### Elasticsearch

```ini
ELASTICSEARCH_URL=https://<ES_HOST>:9200
ELASTICSEARCH_API_KEY=base64encodedapikey
ELASTICSEARCH_INDEX=wazuh-alerts-*
```

Usage:

```python
svc.ingest_from_elasticsearch()
```

### Kafka

```ini
KAFKA_BOOTSTRAP_SERVERS=kafka1:9092,kafka2:9092
KAFKA_TOPIC=wazuh-alerts
KAFKA_GROUP_ID=wazuh-correlation-engine
```

Requires `confluent-kafka` package:

```bash
pip install confluent-kafka
```

Usage:

```python
svc.ingest_from_kafka()
```

---

## Alert Field Mapping

### RawWazuhAlert (as received from Wazuh manager)

| Wazuh JSON field | RawWazuhAlert field | Type |
|---|---|---|
| `timestamp` | `timestamp` | `str` |
| `rule` | `rule` | `dict` |
| `agent` | `agent` | `dict` |
| `data` | `data` | `dict` |
| `location` | `location` | `str` |
| `decoder` | `decoder` | `dict` |
| `id` | `id` | `str` |
| `full_log` | `full_log` | `str` |

### NormalizedAlert (after normalization)

| Field | Source | Example |
|---|---|---|
| `timestamp` | `raw.timestamp` | `2025-03-15T10:30:00Z` |
| `agent_name` | `raw.agent.name` | `agent-01` |
| `host` | `raw.agent.name` or `raw.data.hostname` | `agent-01` |
| `rule_id` | `raw.rule.id` | `5712` |
| `rule_level` | `raw.rule.level` | `7` |
| `rule_description` | `raw.rule.description` | `SSHD brute force attempt` |
| `source_ip` | `raw.data.srcip` or `predecoder.srcip` | `10.0.0.1` |
| `destination_ip` | `raw.data.dstip` | `192.168.1.1` |
| `user` | `raw.data.user` or `predecoder.user` | `root` |
| `event_type` | Derived from `rule.groups` and `rule.description` | `brute_force` |
| `fingerprint` | SHA-256 of normalized fields | *(auto-generated)* |

### Event type classification

| Wazuh rule groups / description keywords | Event type |
|---|---|
| `authentication`, `ssh` | `authentication` |
| `malware`, `virus` | `malware` |
| `privilege`, `escalation` | `privilege_escalation` |
| `lateral`, `remote` | `lateral_movement` |
| `brute`, `bf` | `brute_force` |
| `persistence`, `persist` | `persistence` |
| `exfil`, `exfiltration` | `exfiltration` |
| `discovery`, `recon` | `discovery` |
| *(none of the above)* | `unknown` |

---

## Authentication

### Option A: Long-lived JWT token (recommended for integrations)

```bash
curl -X POST http://<ENGINE_HOST>:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token'
```

Use the token in the `Authorization` header:

```bash
curl -X POST http://<ENGINE_HOST>:8000/api/v1/alerts/ingest \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '@alerts.json'
```

### Option B: Short-lived token (for automation scripts)

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

curl -X POST http://localhost:8000/api/v1/alerts/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @alerts.json
```

### Required permissions

The token must have the `run_analysis` permission:
- **admin** users have it by default
- **analyst** and **senior_analyst** roles also have it

---

## Security Considerations

| Concern | Recommendation |
|---|---|
| **TLS** | Place both services behind a reverse proxy with TLS termination |
| **Network segmentation** | Only the Wazuh manager needs HTTP access to the engine's ingest endpoint |
| **API token rotation** | Rotate the JWT token regularly; use short `JWT_EXPIRE_MINUTES` |
| **Rate limiting** | Per-role rate limiting enforced (admin: 200/min, analyst: 100/min, anonymous: 30/min) |
| **Alert validation** | Invalid records go to the dead-letter queue; no malformed data reaches correlation |
| **Audit trail** | All ingestion requests are logged; review via `GET /api/v1/admin/audit-log` |

---

## Troubleshooting

| Symptom | Likely cause | Solution |
|---|---|---|
| Integration reports "Connection refused" | Engine not running | `curl http://ENGINE_HOST:8000/api/v1/health` |
| Ingestion returns 401 | Invalid or expired JWT | Regenerate via `/auth/login` |
| Ingestion returns 429 | Rate limit exceeded | Increase per-role limits or batch via webhook |
| Alerts ingested but no incidents created | Correlation window too short | Check `CORRELATION_WINDOW_MINUTES` |
| Alerts go to dead-letter queue | JSON doesn't match schema | Check `/admin/dlq` for validation errors |
| Polling fails to authenticate to Wazuh API | Wrong credentials | Test: `curl -u user:pass -k https://WAZUH:55000/security/user/authenticate` |

---

## Testing the Integration

### Send a test alert via curl

```bash
curl -X POST http://localhost:8000/api/v1/alerts/ingest \
  -H "Authorization: Bearer $(curl -s -X POST http://localhost:8000/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{\"username\": \"admin\", \"password\": \"admin123\"}' | jq -r '.access_token')" \
  -H "Content-Type: application/json" \
  -d '[{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "rule": {"id": "5712", "level": 7, "description": "SSHD brute force attempt", "groups": ["ssh", "authentication"]},
    "agent": {"name": "test-agent"},
    "data": {"srcip": "203.0.113.5", "dstip": "192.168.1.10", "user": "root"},
    "location": "/var/log/auth.log",
    "decoder": {"name": "sshd"},
    "full_log": "Failed password for root from 203.0.113.5 port 22 ssh2"
  }]'
```

### Verify in the dashboard

1. Open the dashboard at `http://localhost:8501`
2. Navigate to **Incident Explorer**
3. Check **Admin Panel → DLQ** for rejected alerts
4. Check **Threat Intelligence** for enriched IP data
