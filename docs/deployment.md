# Deployment Guide

## Architecture Overview

| Service | Role | Port |
|---------|------|------|
| **API** | FastAPI backend — ingestion, correlation, enrichment, AI analysis, scoring, reporting, webhooks | `8000` |
| **Dashboard** | Streamlit frontend — SOC overview, incident explorer, admin panel | `8501` |
| **PostgreSQL** *(production only)* | Persistent database | `5432` |

**Internal data directory**: `data/` stores SQLite databases, alert JSON files, reports, and GeoIP databases.

**Wazuh integration**: See [docs/wazuh-integration.md](wazuh-integration.md) for four ways to connect your Wazuh manager (custom integrator, webhook, API polling, or file-based). Additional ingestion sources support Wazuh Indexer, Elasticsearch, and Kafka.

---

## Prerequisites

- Python 3.11+
- Docker & Docker Compose *(optional, for containerized deployment)*
- PostgreSQL 16+ *(optional, for production)*
- GeoIP2 databases *(optional, for enrichment)* — place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in `data/geoip/`

---

## Quick Start (Development)

### 1. Clone and configure

```bash
git clone <repo-url> wazuh-ai-correlation-engine
cd wazuh-ai-correlation-engine
cp .env.example .env
```

Edit `.env` to set your environment values.

### 2. Create virtual environment and install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

### 3. Initialize the database

```bash
alembic upgrade head
```

### 4. Seed default data

```bash
python scripts/seed_data.py
```

Default users:

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| `admin` | `admin123` | admin | Must change password on first login |
| `analyst` | `analyst123` | analyst | Must change password on first login |
| `senior` | `senior123` | senior_analyst | Must change password on first login |

### 5. Generate sample alerts (optional)

```bash
python scripts/generate_alerts.py
```

### 6. Run the API

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

- API: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- Redoc: `http://localhost:8000/redoc`
- Health: `http://localhost:8000/api/v1/health`
- Readiness: `http://localhost:8000/api/v1/ready`
- Metrics: `http://localhost:8000/metrics`

### 7. Run the Dashboard (separate terminal)

```bash
PYTHONPATH=$(pwd) echo "" | nohup streamlit run src/dashboard/app.py --server.port=8501 --server.address=0.0.0.0 &
```

Note: `PYTHONPATH` ensures imports resolve from the project root; the empty pipe (`echo ""`) suppresses Streamlit's email prompt. Run from the project root directory. Start the API first.

Dashboard: `http://localhost:8501`

### 8. Run tests

```bash
# All tests
pytest tests/ integration_tests/ --cov=src --cov-report=term

# Unit tests only
pytest tests/ -v

# Integration tests only
pytest integration_tests/ -v
```

---

## Docker Deployment

### Development (Docker Compose)

```bash
docker compose -f docker-compose.yml up --build
```

Services start automatically. The API health check must pass before the dashboard connects.

### Production (Docker Compose with PostgreSQL)

```bash
# Edit production config
vim config/production.yaml
vim .env

docker compose -f docker-compose.prod.yml up --build -d
```

Services:
- **PostgreSQL 16** with persistent volume
- **API** with PostgreSQL backend
- **Dashboard** pointing to API

### Build individual images

```bash
docker build -f docker/Dockerfile.api -t wazuh-ai-api:latest .
docker build -f docker/Dockerfile.dashboard -t wazuh-ai-dashboard:latest .
```

---

## Production Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `wazuh-ai-correlation-engine` | Service identifier |
| `DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FORMAT` | `json` | Log format (`json` or `text`) |
| `DATABASE_URL` | `sqlite:///data/wazuh_correlator.db` | Database connection string |
| `ALERT_SOURCE` | `local` | Ingestion source type |
| `ALERT_FILE_PATH` | `data/alerts/` | Alert JSON file directory |
| `BATCH_SIZE` | `100` | Ingestion batch size |
| `POLL_INTERVAL_SECONDS` | `30` | File poll interval |
| `WAZUH_API_URL` | *(empty)* | Wazuh REST API v2 endpoint |
| `WAZUH_API_USER` | *(empty)* | Wazuh API username |
| `WAZUH_API_PASSWORD` | *(empty)* | Wazuh API password |
| `WAZUH_INDEXER_URL` | *(empty)* | Wazuh Indexer (OpenSearch) endpoint |
| `WAZUH_INDEXER_USER` | *(empty)* | Wazuh Indexer username |
| `WAZUH_INDEXER_PASSWORD` | *(empty)* | Wazuh Indexer password |
| `ELASTICSEARCH_URL` | *(empty)* | Elasticsearch endpoint |
| `ELASTICSEARCH_API_KEY` | *(empty)* | Elasticsearch API key |
| `KAFKA_BOOTSTRAP_SERVERS` | *(empty)* | Kafka bootstrap servers |
| `KAFKA_TOPIC` | `wazuh-alerts` | Kafka topic name |
| `CORRELATION_WINDOW_MINUTES` | `5` | Correlation time window |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB threat intel API key |
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal threat intel API key |
| `CACHE_TTL_SECONDS` | `3600` | Enrichment cache TTL |
| `CORRELATION_SEMANTIC_THRESHOLD` | `0.85` | Semantic similarity threshold |
| `EMBEDDING_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Embedding model |
| `AI_MODE` | `rule` | AI provider (`rule`, `openai`, `ollama`) |
| `OPENAI_API_KEY` | *(empty)* | OpenAI API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint |
| `DASHBOARD_API_BASE` | `http://localhost:8000/api/v1` | API base URL used by the Streamlit dashboard |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API port |
| `JWT_SECRET` | *(default)* | JWT signing secret **(change in production!)** |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token lifetime |
| `RATE_LIMIT_PER_MINUTE` | `100` | Global API rate limit |
| `RATE_LIMIT_BURST` | `200` | Burst rate limit cap |
| `RATE_LIMIT_ADMIN` | `200` | Admin rate limit (per minute) |
| `RATE_LIMIT_SENIOR_ANALYST` | `150` | Senior analyst rate limit |
| `RATE_LIMIT_ANALYST` | `100` | Analyst rate limit |
| `RATE_LIMIT_ANONYMOUS` | `30` | Unauthenticated rate limit |
| `ALERT_RETENTION_DAYS` | `90` | Alert data retention |
| `INCIDENT_RETENTION_DAYS` | `365` | Incident data retention |
| `CLEANUP_INTERVAL_HOURS` | `24` | Cleanup job interval |

### Configuration files

Settings cascade: `default.yaml` ← `development.yaml` / `production.yaml` ← environment variables.

| File | Purpose |
|------|---------|
| `config/default.yaml` | Base configuration — all settings defined here |
| `config/development.yaml` | Dev overrides (debug mode, SQLite, text logs) |
| `config/production.yaml` | Production overrides (PostgreSQL, Info logs, OpenAI mode) |

---

## API Reference

All API routes are prefixed with `/api/v1`.

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use returned token:
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/incidents
```

### Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/health` | Health check | No |
| `GET` | `/ready` | Readiness check (DB connectivity) | No |
| `POST` | `/auth/login` | Login, returns JWT | No |
| `POST` | `/auth/refresh` | Refresh JWT | Yes |
| `GET` | `/auth/requires-password-change` | Check if password change is required | Yes |
| `POST` | `/auth/change-password` | Change own password | Yes |
| `POST` | `/auth/reset-password` | Reset another user's password | Admin (manage_users) |
| `GET` | `/incidents` | List incidents (paginated, filterable) | Yes |
| `GET` | `/incidents/{id}` | Get incident detail with alerts and feedback | Yes |
| `PUT` | `/incidents/{id}` | Update incident (status, severity, score) | Yes |
| `DELETE` | `/incidents/{id}` | Delete incident | Admin |
| `GET` | `/alerts` | List alerts (paginated) | Yes |
| `GET` | `/alerts/{id}` | Get alert detail | Yes |
| `POST` | `/alerts/ingest` | Ingest Wazuh alerts | Yes |
| `POST` | `/analyze` | Run AI analysis on an incident | Yes |
| `POST` | `/analyze/alert` | Run AI analysis on a single alert | Yes |
| `POST` | `/incidents/merge` | Merge multiple incidents into one | Senior+ |
| `POST` | `/incidents/{id}/split` | Split incident, move alerts | Senior+ |
| `POST` | `/incidents/{id}/feedback` | Add analyst feedback | Senior+ |
| `GET` | `/incidents/{id}/feedback` | List feedback for an incident | Yes |
| `POST` | `/incidents/{id}/ai-override` | Override AI analysis conclusions | Senior+ |
| `POST` | `/incidents/{id}/report` | Generate report (JSON, HTML, PDF) | Yes |
| `GET` | `/admin/dlq` | List dead-letter queue records | Admin |
| `POST` | `/admin/dlq/{id}/retry` | Retry a DLQ record | Admin |
| `POST` | `/admin/dlq/{id}/discard` | Discard a DLQ record | Admin |
| `POST` | `/admin/dlq/retry-all` | Retry all pending DLQ records | Admin |
| `GET` | `/admin/stats` | System statistics (analysts with `view_dashboard` can also access) | Yes |
| `GET` | `/admin/users` | List all users | Admin (manage_users) |
| `GET` | `/admin/audit-log` | List audit log entries | Admin |
| `GET` | `/admin/config` | View configuration (secrets redacted) | Admin |
| `GET` | `/admin/correlation-stats` | False-positive rates per rule | Admin |
| `GET` | `/admin/scoring-baseline` | Historical risk score baseline | Admin |
| `POST` | `/webhooks/configure` | Register a webhook | Admin |
| `GET` | `/webhooks` | List registered webhooks | Admin |
| `DELETE` | `/webhooks/{id}` | Unregister a webhook | Admin |

---

## Database Migrations

```bash
alembic revision --autogenerate -m "description"
alembic upgrade head
alembic downgrade -1
alembic history
```

The Alembic configuration reads `DATABASE_URL` from the environment.

---

## Database Backends

### SQLite (development)

```yaml
# config/development.yaml
database:
  url: sqlite:///data/wazuh_correlator.db
```

### PostgreSQL (production)

```yaml
# config/production.yaml
database:
  url: postgresql://user:password@host:5432/wazuh_correlator
  pool_size: 20
  max_overflow: 30
```

Run migrations before starting the API:

```bash
alembic upgrade head
```

---

## Management Scripts

| Script | Purpose | Frequency |
|--------|---------|-----------|
| `scripts/seed_data.py` | Create admin users + sample data | Once (initial setup) |
| `scripts/generate_alerts.py` | Generate sample Wazuh alert JSON files | As needed (testing) |
| `scripts/cleanup.py` | Purge expired records per retention policy | Cron (e.g., daily) |

### Data retention cleanup

```bash
# Dry run
python scripts/cleanup.py
```

Recommended cron entry (daily):

```cron
0 3 * * * cd /opt/wazuh-ai-correlation-engine && /path/to/venv/bin/python scripts/cleanup.py
```

---

## Threat Intelligence Configuration

### AbuseIPDB

1. Sign up at [abuseipdb.com](https://www.abuseipdb.com) and get an API key
2. Set `ABUSEIPDB_API_KEY` in `.env` or `config/production.yaml`

### VirusTotal

1. Sign up at [virustotal.com](https://www.virustotal.com) and get an API key
2. Set `VIRUSTOTAL_API_KEY` in `.env` or `config/production.yaml`

### GeoIP / ASN

1. Download MaxMind GeoLite2 databases from [dev.maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. Place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in `data/geoip/`

All providers gracefully degrade when unconfigured.

---

## Semantic Correlation

The engine includes a **semantic-based correlation rule** that groups alerts by ML embedding similarity using `fastembed`. Vectors are 384-dimensional; groups form when cosine similarity exceeds the threshold.

```yaml
correlation:
  rules:
    - time_based
    - asset_based
    - user_based
    - network_based
    - rule_based
    - semantic_based
  semantic_threshold: 0.85

embedding:
  model: sentence-transformers/all-MiniLM-L6-v2
  dimension: 384
```

The model downloads automatically on first use. No GPU or API key required. Falls back to deterministic hash-based encoding if the model fails to load.

---

## AI Provider Configuration

### Rule-based (default, no API key)

```yaml
ai:
  mode: rule
```

### OpenAI

```yaml
ai:
  mode: openai
  providers:
    openai:
      model: gpt-4
```

### Ollama (local LLM)

```yaml
ai:
  mode: ollama
  providers:
    ollama:
      url: http://localhost:11434
      model: llama3
```

---

## Grafana Monitoring

A pre-built SOC dashboard is at `docker/grafana/dashboards/soc-dashboard.json`.

### Setup

1. Deploy Prometheus + Grafana
2. Configure Prometheus to scrape `http://<api-host>:8000/metrics`
3. Import the dashboard JSON

The `/metrics` endpoint exposes:
- `alerts_processed_total` — ingestion counts by source/status
- `incidents_generated_total` — incidents by severity
- `api_request_duration_seconds` — request latency by endpoint/method/status
- `ai_processing_duration_seconds` — AI analysis latency by provider
- `enrichment_lookup_duration_seconds` — enrichment latency by provider/status
- `dlq_size` — dead-letter queue depth
- `active_incidents` — open incidents by severity
- `cache_hit_ratio` — enrichment cache hit rate

---

## CI/CD Pipeline

The `.github/workflows/ci.yml` pipeline runs on push/PR to `main`/`develop`:

| Stage | Tools | Description |
|-------|-------|-------------|
| **lint** | `ruff` | Code style and import sorting |
| **security** | `bandit` | Static security analysis |
| **typecheck** | `mypy` | Static type checking |
| **test** | `pytest`, `pytest-cov` | Unit tests with coverage (80% minimum) |
| **integration** | `pytest` + Docker Compose | Integration tests and smoke test |
| **build** | `build` | Python package build |
| **docker** | Docker buildx | Container image build (main branch only) |

---

## RBAC Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access — all CRUD, admin stats, DLQ, webhooks, audit log, config view, user management |
| `senior_analyst` | Read/write on incidents/alerts, AI analysis, reporting, merge/split, feedback, override AI |
| `analyst` | Read on incidents/alerts, AI analysis, reporting, dashboard stats (`view_dashboard`) |

---

## Webhooks

Webhooks deliver real-time event notifications with HMAC-SHA256 signing and automatic retry.

```bash
curl -X POST http://localhost:8000/api/v1/webhooks/configure \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.example.com/events", "events": ["incident_created", "incident_updated"], "secret": "my-signing-secret"}'
```

---

## Rate Limiting

Per-role rate limiting with sliding window counters:

| Role | Sustained (req/min) | Burst multiplier |
|------|---------------------|-----------------|
| admin | 200 | 1.5x |
| senior_analyst | 150 | 1.33x |
| analyst | 100 | 1.5x |
| anonymous | 30 | 1.0x |

Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`) are included in all API responses.

---

## Troubleshooting

| Symptom | Likely cause | Solution |
|---------|-------------|----------|
| `/ready` returns 503 | DB not initialized | Run `alembic upgrade head` |
| Login returns 401 | Wrong credentials or missing seed data | Run `python scripts/seed_data.py` |
| Login requires password change | First-time login with seed data | Use `/auth/change-password` endpoint or the dashboard to set a new password |
| Enrichment returns `None` for all IPs | No API keys configured | Set `ABUSEIPDB_API_KEY` or `VIRUSTOTAL_API_KEY` |
| AI analysis returns rule-based results | No AI API key | Set `OPENAI_API_KEY` or switch to `AI_MODE=rule` |
| Docker build fails | `docker` CLI not available | Install Docker or use bare-metal deployment |
| Dashboard can't connect to API | `API_HOST` env var not set | Set `API_HOST=http://localhost:8000` |
| Ingestion returns 429 | Rate limit exceeded | Increase `RATE_LIMIT_PER_MINUTE` or use batched webhook |
| Alerts go to dead-letter queue | JSON doesn't match schema | Check `/admin/dlq` for validation errors |

---

## Directory Structure

```
wazuh-ai-correlation-engine/
├── alembic/                # Database migrations
├── config/                 # YAML configuration files
├── data/                   # Runtime data (DB, alerts, reports, GeoIP)
├── docker/                 # Dockerfiles + Grafana dashboard
├── docs/                   # Documentation
├── scripts/                # Management scripts
├── src/                    # Application source
│   ├── ai/                 # AI analysis (rule, OpenAI, Ollama)
│   ├── api/                # FastAPI application & routes
│   ├── core/               # Database, config, logging, cache, models
│   ├── correlation/        # Correlation engine + embedding + vector store
│   ├── dashboard/          # Streamlit SOC dashboard
│   ├── deduplication/      # Alert deduplication
│   ├── enrichment/         # Threat intel providers
│   ├── ingestion/          # Alert ingestion + DLQ
│   ├── normalization/      # Pydantic schemas
│   ├── reporting/          # Report generation (JSON/HTML/PDF)
│   ├── scoring/            # Risk scoring & MITRE ATT&CK
│   └── webhooks/           # Webhook delivery engine
├── tests/                  # Unit tests
├── integration_tests/      # Integration & E2E tests
├── .env.example
├── docker-compose.yml
├── docker-compose.prod.yml
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```
