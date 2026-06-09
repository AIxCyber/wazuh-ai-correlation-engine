🚀 I built an AI-powered correlation engine for Wazuh SIEM — and here's why.

**The problem:** SOC teams drown in thousands of raw alerts daily. Manual correlation is slow, inconsistent, and doesn't scale. False positives burn analyst time, and without automated enrichment and risk scoring, critical threats slip through the cracks.

**What I built:** An open-source platform that ingests alerts from Wazuh, Elasticsearch, Kafka, and file sources — normalizes, deduplicates, and correlates them into incidents using 6 pluggable rule types. What's innovative? A semantic correlation rule that uses ML embeddings to group semantically similar alerts even when they don't match traditional rule patterns. A false-positive feedback loop that automatically adjusts rule weights over time — the more analysts mark, the smarter the engine gets. Multi-factor risk scoring with MITRE ATT&CK mapping. And AI analysis via rule-based tables (zero config), OpenAI GPT, or local Ollama models for air-gapped environments.

**Tech stack:** FastAPI backend (RBAC, per-role rate limiting, Prometheus metrics, dead-letter queue, audit trail), Streamlit dark-themed SOC dashboard (incident explorer, threat intel viewer, reporting, admin panels), Postgres/SQLite, HMAC-signed webhooks, Docker. 203 tests passing.

After building this end-to-end — from data ingestion to AI analysis to SOC dashboard — I'm convinced that open-source, AI-augmented SIEM correlation is the way forward for lean security teams.

#cybersecurity #wazuh #siem #fastapi #streamlit #threatintelligence #infosec #python #ai #opensource #soc
