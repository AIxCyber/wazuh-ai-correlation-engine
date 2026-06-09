
import json
import os
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from src.core.config import get_config
from src.core.logging import get_logger
from src.core.metrics import alerts_processed
from src.ingestion.dlq import DeadLetterQueue
from src.normalization.normalizer import normalize_wazuh_alert
from src.normalization.schema import NormalizedAlert, RawWazuhAlert

logger = get_logger(__name__)


def _process_raw_items(items: list[dict[str, Any]], dlq: DeadLetterQueue, source: str) -> list[NormalizedAlert]:
    alerts: list[NormalizedAlert] = []
    for item in items:
        try:
            raw = RawWazuhAlert(**item)
            alert = normalize_wazuh_alert(raw)
            alerts.append(alert)
        except Exception as e:
            dlq.add(
                original_payload=item,
                error=str(e),
                error_type=type(e).__name__,
                source=source,
            )
            alerts_processed.labels(source=source, status="failed").inc()
    return alerts


class AlertIngestionService:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.dlq = DeadLetterQueue()
        self._buffer: list[NormalizedAlert] = []

    def ingest_from_local(self, file_path: str | None = None) -> list[NormalizedAlert]:
        path = file_path or self.cfg.alert_file_path
        alerts: list[NormalizedAlert] = []

        if os.path.isfile(path):
            alerts.extend(self._process_file(path))
        elif os.path.isdir(path):
            for fname in sorted(os.listdir(path)):
                if fname.endswith(".json"):
                    fpath = os.path.join(path, fname)
                    alerts.extend(self._process_file(fpath))

        alerts_processed.labels(source="local", status="success").inc(len(alerts))
        logger.info("ingested_alerts", extra={"count": len(alerts), "source": "local"})
        return alerts

    def _process_file(self, file_path: str) -> list[NormalizedAlert]:
        results: list[NormalizedAlert] = []
        try:
            with open(file_path) as f:
                data = json.load(f)

            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                logger.warning("unexpected_json_format", extra={"file": file_path})
                return results

            for item in data:
                try:
                    raw = RawWazuhAlert(**item)
                    alert = normalize_wazuh_alert(raw)
                    results.append(alert)
                except Exception as e:
                    self.dlq.add(
                        original_payload=item,
                        error=str(e),
                        error_type=type(e).__name__,
                        source="ingestion_service",
                    )
                    alerts_processed.labels(source="local", status="failed").inc()

        except json.JSONDecodeError as e:
            logger.error("json_decode_error", extra={"file": file_path, "error": str(e)})
        except Exception as e:
            logger.error("file_read_error", extra={"file": file_path, "error": str(e)})

        return results

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
    )
    def ingest_from_api(self, url: str, api_key: str) -> list[NormalizedAlert]:
        import httpx

        logger.info("fetching_alerts_from_api", extra={"url": url})
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", data if isinstance(data, list) else [data])
        alerts = _process_raw_items(items, self.dlq, "api")
        alerts_processed.labels(source="api", status="success").inc(len(alerts))
        logger.info("ingested_alerts_from_api", extra={"count": len(alerts)})
        return alerts

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
    )
    def ingest_from_wazuh_api(self) -> list[NormalizedAlert]:
        import httpx

        cfg = get_config()
        if not cfg.wazuh_api_url:
            logger.error("wazuh_api_url not configured")
            return []
        logger.info("fetching_from_wazuh_api", extra={"url": cfg.wazuh_api_url})
        auth_resp = httpx.post(
            f"{cfg.wazuh_api_url}/security/user/authenticate",
            auth=(cfg.wazuh_api_user, cfg.wazuh_api_password),
            verify=cfg.wazuh_api_verify_ssl,
            timeout=30,
        )
        auth_resp.raise_for_status()
        token = auth_resp.json().get("data", {}).get("token", "")

        resp = httpx.get(
            f"{cfg.wazuh_api_url}/alerts",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": cfg.batch_size, "sort": "-timestamp"},
            verify=cfg.wazuh_api_verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", {}).get("affected_items", [])
        alerts = _process_raw_items(items, self.dlq, "wazuh_api")
        alerts_processed.labels(source="wazuh_api", status="success").inc(len(alerts))
        logger.info("ingested_from_wazuh_api", extra={"count": len(alerts)})
        return alerts

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
    )
    def ingest_from_wazuh_indexer(self) -> list[NormalizedAlert]:
        import httpx

        cfg = get_config()
        if not cfg.wazuh_indexer_url:
            logger.error("wazuh_indexer_url not configured")
            return []
        logger.info("fetching_from_indexer", extra={"url": cfg.wazuh_indexer_url})
        auth = (cfg.wazuh_indexer_user, cfg.wazuh_indexer_password)
        resp = httpx.post(
            f"{cfg.wazuh_indexer_url}/{cfg.wazuh_indexer_index}/_search",
            json={
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": cfg.batch_size,
            },
            auth=auth,
            verify=cfg.wazuh_indexer_verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        items = [h["_source"] for h in data.get("hits", {}).get("hits", [])]
        alerts = _process_raw_items(items, self.dlq, "wazuh_indexer")
        alerts_processed.labels(source="wazuh_indexer", status="success").inc(len(alerts))
        logger.info("ingested_from_indexer", extra={"count": len(alerts)})
        return alerts

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
    )
    def ingest_from_elasticsearch(self) -> list[NormalizedAlert]:
        import httpx

        cfg = get_config()
        if not cfg.elasticsearch_url:
            logger.error("elasticsearch_url not configured")
            return []
        logger.info("fetching_from_elasticsearch", extra={"url": cfg.elasticsearch_url})
        headers = {"Authorization": f"ApiKey {cfg.elasticsearch_api_key}"} if cfg.elasticsearch_api_key else {}
        resp = httpx.post(
            f"{cfg.elasticsearch_url}/{cfg.elasticsearch_index}/_search",
            json={
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": cfg.batch_size,
            },
            headers=headers or None,
            verify=cfg.elasticsearch_verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        items = [h["_source"] for h in data.get("hits", {}).get("hits", [])]
        alerts = _process_raw_items(items, self.dlq, "elasticsearch")
        alerts_processed.labels(source="elasticsearch", status="success").inc(len(alerts))
        logger.info("ingested_from_elasticsearch", extra={"count": len(alerts)})
        return alerts

    def ingest_from_kafka(self, timeout_ms: int = 5000) -> list[NormalizedAlert]:
        cfg = get_config()
        if not cfg.kafka_bootstrap_servers:
            logger.error("kafka_bootstrap_servers not configured")
            return []
        try:
            from confluent_kafka import Consumer, KafkaException
        except ImportError:
            logger.error("confluent_kafka not installed; pip install confluent-kafka")
            return []

        logger.info("consuming_from_kafka", extra={"servers": cfg.kafka_bootstrap_servers, "topic": cfg.kafka_topic})
        consumer = Consumer({
            "bootstrap.servers": cfg.kafka_bootstrap_servers,
            "group.id": cfg.kafka_group_id,
            "security.protocol": cfg.kafka_security_protocol,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        })
        consumer.subscribe([cfg.kafka_topic])

        items: list[dict[str, Any]] = []
        try:
            while len(items) < cfg.batch_size:
                msg = consumer.poll(timeout=timeout_ms / 1000.0)
                if msg is None:
                    break
                if msg.error():
                    logger.error("kafka_error", extra={"error": msg.error().str()})
                    continue
                try:
                    items.append(json.loads(msg.value().decode("utf-8")))
                except (json.JSONDecodeError, AttributeError) as e:
                    self.dlq.add(
                        original_payload={"raw": str(msg.value())},
                        error=str(e),
                        error_type=type(e).__name__,
                        source="kafka",
                    )
        finally:
            consumer.close()

        alerts = _process_raw_items(items, self.dlq, "kafka")
        alerts_processed.labels(source="kafka", status="success").inc(len(alerts))
        logger.info("consumed_from_kafka", extra={"count": len(alerts)})
        return alerts

    def buffer_alert(self, alert: NormalizedAlert) -> None:
        self._buffer.append(alert)
        if len(self._buffer) >= self.cfg.batch_size:
            self.flush_buffer()

    def flush_buffer(self) -> list[NormalizedAlert]:
        batch = list(self._buffer)
        self._buffer.clear()
        return batch

    def ingest_single(self, raw_data: dict[str, Any]) -> NormalizedAlert | None:
        try:
            raw = RawWazuhAlert(**raw_data)
            alert = normalize_wazuh_alert(raw)
            alerts_processed.labels(source="manual", status="success").inc()
            return alert
        except Exception as e:
            self.dlq.add(
                original_payload=raw_data,
                error=str(e),
                error_type=type(e).__name__,
                source="manual_ingest",
            )
            alerts_processed.labels(source="manual", status="failed").inc()
            return None
