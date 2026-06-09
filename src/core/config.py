
import os
from functools import lru_cache
from typing import Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    app_name: str = "wazuh-ai-correlation-engine"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # Database
    database_url: str = "sqlite:///data/wazuh_correlator.db"
    database_pool_size: int = 5
    database_max_overflow: int = 10

    # Ingestion
    alert_source: str = "local"
    alert_file_path: str = "data/alerts/"
    batch_size: int = 100
    poll_interval_seconds: int = 30
    retry_max_attempts: int = 3
    retry_base_delay: float = 1.0
    retry_max_delay: float = 30.0

    # Wazuh API Source
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_ssl: bool = True

    # Wazuh Indexer Source (OpenSearch-compatible)
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: str = ""
    wazuh_indexer_index: str = "wazuh-alerts-*"
    wazuh_indexer_verify_ssl: bool = True

    # Elasticsearch Source
    elasticsearch_url: str = ""
    elasticsearch_api_key: str = ""
    elasticsearch_index: str = "wazuh-alerts-*"
    elasticsearch_verify_ssl: bool = True

    # Kafka Source
    kafka_bootstrap_servers: str = ""
    kafka_topic: str = "wazuh-alerts"
    kafka_group_id: str = "wazuh-correlation-engine"
    kafka_security_protocol: str = "PLAINTEXT"

    # Correlation
    correlation_window_minutes: int = 5
    correlation_semantic_threshold: float = 0.85
    correlation_rules: list[str] = Field(
        default_factory=lambda: [
            "time_based", "asset_based", "user_based",
            "network_based", "rule_based", "semantic_based",
        ]
    )

    # Embedding
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dim: int = 384

    # Enrichment
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    enable_cache: bool = True
    cache_ttl_seconds: int = 3600
    geoip_db_path: str = "data/geoip/GeoLite2-City.mmdb"
    asn_db_path: str = "data/geoip/GeoLite2-ASN.mmdb"

    # AI
    ai_mode: Literal["rule", "openai", "local"] = "rule"
    openai_api_key: str = ""
    openai_model: str = "gpt-4"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 200
    rate_limit_admin: int = 200
    rate_limit_senior_analyst: int = 150
    rate_limit_analyst: int = 100
    rate_limit_anonymous: int = 30

    # Dashboard
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 8501
    dashboard_api_base: str = "http://localhost:8000/api/v1"

    # SMTP (optional — for forgot-password email delivery)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    # Retention
    alert_retention_days: int = 90
    incident_retention_days: int = 365
    audit_log_retention_days: int = 365
    webhook_log_retention_days: int = 30
    cleanup_interval_hours: int = 24


def load_yaml_config(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


@lru_cache
def get_config() -> AppConfig:
    base = load_yaml_config("config/default.yaml")
    env = os.getenv("APP_ENV", "development")
    env_path = f"config/{env}.yaml"
    overrides = load_yaml_config(env_path)

    merged = {**base, **overrides}
    cfg = AppConfig(**merged)

    if cfg.jwt_secret == "change-me-in-production" and not cfg.debug:
        import warnings
        warnings.warn(
            "JWT_SECRET is set to default value. Change it in production!",
            RuntimeWarning,
        )

    return cfg
