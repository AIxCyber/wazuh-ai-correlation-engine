
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.core.cache import get_cache
from src.core.config import get_config
from src.core.logging import get_logger
from src.core.metrics import cache_hit_ratio, enrichment_lookup_duration
from src.normalization.schema import ThreatIntelResult

logger = get_logger(__name__)


class EnrichmentProvider(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def enrich(self, ip: str) -> ThreatIntelResult | None: ...


class AbuseIPDBProvider(EnrichmentProvider):
    def __init__(self) -> None:
        self.cfg = get_config()
        self.cache = get_cache()

    def name(self) -> str:
        return "abuseipdb"

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=10))
    def enrich(self, ip: str) -> ThreatIntelResult | None:
        if not self.cfg.abuseipdb_api_key:
            logger.debug("abuseipdb_api_key_not_configured")
            return None

        cache_key = f"abuseipdb:{ip}"
        cached = self.cache.get_with_metrics(cache_key)
        if cached:
            return ThreatIntelResult(**cached)

        start = time.time()
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.cfg.abuseipdb_api_key, "Accept": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            result = ThreatIntelResult(
                ip=ip,
                reputation="malicious" if data.get("abuseConfidenceScore", 0) > 50 else "clean",
                confidence=float(data.get("abuseConfidenceScore", 0)),
                country=data.get("countryCode"),
                isp=data.get("isp"),
                last_reported=_parse_date(data.get("lastReportedAt")),
                reports_count=data.get("totalReports", 0),
                categories=data.get("categories", []),
                source="abuseipdb",
            )

            self.cache.set(cache_key, result.model_dump())
            enrichment_lookup_duration.labels(provider="abuseipdb", status="success").observe(
                time.time() - start
            )
            return result

        except httpx.HTTPError as e:
            enrichment_lookup_duration.labels(provider="abuseipdb", status="failed").observe(
                time.time() - start
            )
            logger.error("abuseipdb_lookup_failed", extra={"ip": ip, "error": str(e)})
            return None


class VirusTotalProvider(EnrichmentProvider):
    def __init__(self) -> None:
        self.cfg = get_config()
        self.cache = get_cache()

    def name(self) -> str:
        return "virustotal"

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=10))
    def enrich(self, ip: str) -> ThreatIntelResult | None:
        if not self.cfg.virustotal_api_key:
            logger.debug("virustotal_api_key_not_configured")
            return None

        cache_key = f"virustotal:{ip}"
        cached = self.cache.get_with_metrics(cache_key)
        if cached:
            return ThreatIntelResult(**cached)

        start = time.time()
        try:
            resp = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.cfg.virustotal_api_key},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})

            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            result = ThreatIntelResult(
                ip=ip,
                reputation="malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean",
                confidence=float(malicious) / max(stats.get("total", 1), 1) * 100,
                country=data.get("country"),
                asn=data.get("asn"),
                isp=data.get("as_owner"),
                last_reported=_parse_date(data.get("last_analysis_date")),
                reports_count=malicious,
                categories=[],  # VT doesn't categorize IPs like AbuseIPDB
                source="virustotal",
            )

            self.cache.set(cache_key, result.model_dump())
            enrichment_lookup_duration.labels(provider="virustotal", status="success").observe(
                time.time() - start
            )
            return result

        except httpx.HTTPError as e:
            enrichment_lookup_duration.labels(provider="virustotal", status="failed").observe(
                time.time() - start
            )
            logger.error("virustotal_lookup_failed", extra={"ip": ip, "error": str(e)})
            return None


class GeoIPProvider(EnrichmentProvider):
    def __init__(self) -> None:
        self.cfg = get_config()
        self.cache = get_cache()
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(self.cfg.geoip_db_path)
            except (ImportError, FileNotFoundError, ValueError):
                logger.warning("geoip_database_not_available")
                self._reader = None
        return self._reader

    def name(self) -> str:
        return "geoip"

    def enrich(self, ip: str) -> ThreatIntelResult | None:
        cache_key = f"geoip:{ip}"
        cached = self.cache.get_with_metrics(cache_key)
        if cached:
            return ThreatIntelResult(**cached)

        reader = self._get_reader()
        if not reader:
            return None

        start = time.time()
        try:
            response = reader.city(ip)
            result = ThreatIntelResult(
                ip=ip,
                country=response.country.name,
                source="geoip",
            )
            self.cache.set(cache_key, result.model_dump())
            enrichment_lookup_duration.labels(provider="geoip", status="success").observe(
                time.time() - start
            )
            return result
        except Exception as e:
            logger.debug("geoip_lookup_failed", extra={"ip": ip, "error": str(e)})
            return None


class ASNProvider(EnrichmentProvider):
    def __init__(self) -> None:
        self.cfg = get_config()
        self.cache = get_cache()
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(self.cfg.asn_db_path)
            except (ImportError, FileNotFoundError, ValueError):
                logger.warning("asn_database_not_available")
                self._reader = None
        return self._reader

    def name(self) -> str:
        return "asn"

    def enrich(self, ip: str) -> ThreatIntelResult | None:
        cache_key = f"asn:{ip}"
        cached = self.cache.get_with_metrics(cache_key)
        if cached:
            return ThreatIntelResult(**cached)

        reader = self._get_reader()
        if not reader:
            return None

        start = time.time()
        try:
            response = reader.asn(ip)
            result = ThreatIntelResult(
                ip=ip,
                asn=f"AS{response.autonomous_system_number}",
                isp=response.autonomous_system_organization,
                source="asn",
            )
            self.cache.set(cache_key, result.model_dump())
            enrichment_lookup_duration.labels(provider="asn", status="success").observe(
                time.time() - start
            )
            return result
        except Exception as e:
            logger.debug("asn_lookup_failed", extra={"ip": ip, "error": str(e)})
            return None


class EnrichmentEngine:
    def __init__(self) -> None:
        self.providers: list[EnrichmentProvider] = [
            AbuseIPDBProvider(),
            VirusTotalProvider(),
            GeoIPProvider(),
            ASNProvider(),
        ]
        self.cfg = get_config()

    def enrich_ip(self, ip: str) -> dict[str, Any]:
        results: dict[str, Any] = {"ip": ip, "enrichments": {}}

        for provider in self.providers:
            try:
                result = provider.enrich(ip)
                if result:
                    results["enrichments"][provider.name()] = result.model_dump(exclude_none=True)
            except Exception as e:
                logger.error(
                    "enrichment_error",
                    extra={"provider": provider.name(), "ip": ip, "error": str(e)},
                )

        # Merge top-level fields from best available source
        for src in ("abuseipdb", "virustotal", "geoip", "asn"):
            entry = results["enrichments"].get(src, {})
            if entry.get("reputation"):
                results["reputation"] = entry["reputation"]
            if entry.get("confidence"):
                results["confidence"] = entry["confidence"]
            if entry.get("country") and "country" not in results:
                results["country"] = entry["country"]
            if entry.get("asn") and "asn" not in results:
                results["asn"] = entry["asn"]
            if entry.get("isp") and "isp" not in results:
                results["isp"] = entry["isp"]

        cache_hit_ratio.set(get_cache().hit_ratio)
        return results

    def enrich_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        source_ips = incident.get("source_ips", [])
        enriched_ips = {}
        for ip in source_ips:
            enriched_ips[ip] = self.enrich_ip(ip)

        incident["threat_intel"] = enriched_ips

        # Update risk factors
        has_threat_hit = any(
            e.get("reputation") == "malicious"
            for ip_data in enriched_ips.values()
            for e in [ip_data.get("enrichments", {}).get("abuseipdb", {})]
        )
        incident["threat_intel_hit"] = has_threat_hit
        return incident


def _parse_date(date_val: Any) -> Any:
    if isinstance(date_val, str):
        from datetime import datetime
        try:
            return datetime.fromisoformat(date_val.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
    return None
