from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.core.cache import get_cache
from src.enrichment.engine import (
    AbuseIPDBProvider,
    ASNProvider,
    EnrichmentEngine,
    GeoIPProvider,
    VirusTotalProvider,
    _parse_date,
)
from src.normalization.schema import ThreatIntelResult


def _clear_cache():
    get_cache().clear()


@pytest.fixture(autouse=True)
def _clear_enrichment_cache():
    _clear_cache()


def test_enrichment_engine_initialization():
    engine = EnrichmentEngine()
    assert len(engine.providers) == 4
    assert any(isinstance(p, AbuseIPDBProvider) for p in engine.providers)
    assert any(isinstance(p, VirusTotalProvider) for p in engine.providers)
    assert any(isinstance(p, GeoIPProvider) for p in engine.providers)
    assert any(isinstance(p, ASNProvider) for p in engine.providers)


def test_enrich_ip_local_only():
    """GeoIP and ASN may not have databases, but should not crash."""
    engine = EnrichmentEngine()
    result = engine.enrich_ip("203.0.113.5")
    assert result["ip"] == "203.0.113.5"
    assert "enrichments" in result


def test_enrich_incident_with_ips():
    engine = EnrichmentEngine()
    incident = {
        "source_ips": ["203.0.113.5", "198.51.100.20"],
        "title": "Test Incident",
    }
    result = engine.enrich_incident(incident)
    assert "threat_intel" in result
    assert len(result["threat_intel"]) == 2
    assert "threat_intel_hit" in result


def test_enrich_empty_incident():
    engine = EnrichmentEngine()
    incident = {"source_ips": [], "title": "Empty"}
    result = engine.enrich_incident(incident)
    assert result["threat_intel"] == {}
    assert not result["threat_intel_hit"]


def test_abuseipdb_disabled():
    provider = AbuseIPDBProvider()
    result = provider.enrich("203.0.113.5")
    assert result is None


def test_virustotal_disabled():
    provider = VirusTotalProvider()
    result = provider.enrich("203.0.113.5")
    assert result is None


@patch("httpx.get")
def test_abuseipdb_enrich_success(mock_get):
    provider = AbuseIPDBProvider()
    provider.cfg.abuseipdb_api_key = "test-key"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "isp": "Test ISP",
            "totalReports": 10,
            "categories": ["port_scan"],
        }
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    result = provider.enrich("203.0.113.5")
    assert result is not None
    assert result.reputation == "malicious"
    assert result.confidence == 85.0
    assert result.country == "US"
    assert result.isp == "Test ISP"
    assert result.reports_count == 10
    mock_get.assert_called_once()


@patch("httpx.get")
def test_abuseipdb_enrich_clean(mock_get):
    provider = AbuseIPDBProvider()
    provider.cfg.abuseipdb_api_key = "test-key"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 10,
            "countryCode": "CA",
        }
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    result = provider.enrich("8.8.8.8")
    assert result is not None
    assert result.reputation == "clean"
    assert result.confidence == 10.0


@patch("httpx.get")
def test_abuseipdb_enrich_http_error(mock_get):
    provider = AbuseIPDBProvider()
    provider.cfg.abuseipdb_api_key = "test-key"
    mock_get.side_effect = httpx.HTTPError("API error")

    result = provider.enrich("203.0.113.5")
    assert result is None


@patch("httpx.get")
def test_abuseipdb_cache_hit(mock_get):
    provider = AbuseIPDBProvider()
    provider.cfg.abuseipdb_api_key = "test-key"

    cached_result = ThreatIntelResult(
        ip="203.0.113.5", reputation="malicious", confidence=95.0, source="abuseipdb"
    )
    provider.cache.set("abuseipdb:203.0.113.5", cached_result.model_dump())

    result = provider.enrich("203.0.113.5")
    assert result is not None
    assert result.reputation == "malicious"
    mock_get.assert_not_called()


@patch("httpx.get")
def test_virustotal_enrich_success(mock_get):
    provider = VirusTotalProvider()
    provider.cfg.virustotal_api_key = "vt-test-key"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 1, "total": 60},
                "country": "US",
                "asn": "AS15169",
                "as_owner": "Google LLC",
            }
        }
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    result = provider.enrich("8.8.8.8")
    assert result is not None
    assert result.reputation == "malicious"
    assert result.confidence == 5.0
    assert result.country == "US"
    assert result.asn == "AS15169"
    assert result.source == "virustotal"
    mock_get.assert_called_once()


@patch("httpx.get")
def test_virustotal_enrich_clean(mock_get):
    provider = VirusTotalProvider()
    provider.cfg.virustotal_api_key = "vt-key"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "total": 60},
            }
        }
    }
    mock_resp.is_success = True
    mock_get.return_value = mock_resp

    result = provider.enrich("8.8.8.8")
    assert result is not None
    assert result.reputation == "clean"
    assert result.confidence == 0.0


@patch("httpx.get")
def test_virustotal_cache_hit(mock_get):
    provider = VirusTotalProvider()
    provider.cfg.virustotal_api_key = "vt-key"

    cached_result = ThreatIntelResult(
        ip="8.8.8.8", reputation="clean", confidence=0.0, source="virustotal"
    )
    provider.cache.set("virustotal:8.8.8.8", cached_result.model_dump())

    result = provider.enrich("8.8.8.8")
    assert result is not None
    mock_get.assert_not_called()


@patch("httpx.get")
def test_virustotal_enrich_http_error(mock_get):
    provider = VirusTotalProvider()
    provider.cfg.virustotal_api_key = "vt-key"
    mock_get.side_effect = httpx.HTTPError("VT error")

    result = provider.enrich("8.8.8.8")
    assert result is None


def test_enrich_ip_with_enrichment_data():
    engine = EnrichmentEngine()

    abuse_result = ThreatIntelResult(
        ip="1.2.3.4", reputation="malicious", confidence=90.0,
        country="RU", source="abuseipdb",
    )

    with patch.object(engine.providers[0], "enrich", return_value=abuse_result), \
         patch.object(engine.providers[1], "enrich", return_value=None), \
         patch.object(engine.providers[2], "enrich", return_value=None), \
         patch.object(engine.providers[3], "enrich", return_value=None):
        result = engine.enrich_ip("1.2.3.4")

        assert result["ip"] == "1.2.3.4"
        assert result["enrichments"]["abuseipdb"]["reputation"] == "malicious"
        assert result["reputation"] == "malicious"
        assert result["country"] == "RU"


def test_enrich_ip_provider_exception():
    engine = EnrichmentEngine()
    with patch.object(engine.providers[0], "enrich", side_effect=Exception("Unexpected")), \
         patch.object(engine.providers[1], "enrich", return_value=None), \
         patch.object(engine.providers[2], "enrich", return_value=None), \
         patch.object(engine.providers[3], "enrich", return_value=None):
        result = engine.enrich_ip("1.2.3.4")
        assert result["ip"] == "1.2.3.4"


def test_geoip_provider_no_database():
    provider = GeoIPProvider()
    result = provider.enrich("203.0.113.5")
    assert result is None


def test_asn_provider_no_database():
    provider = ASNProvider()
    result = provider.enrich("203.0.113.5")
    assert result is None


def test_geoip_cache_hit():
    provider = GeoIPProvider()
    cached = ThreatIntelResult(ip="1.2.3.4", country="US", source="geoip")
    provider.cache.set("geoip:1.2.3.4", cached.model_dump())

    result = provider.enrich("1.2.3.4")
    assert result is not None
    assert result.country == "US"


def test_asn_cache_hit():
    provider = ASNProvider()
    cached = ThreatIntelResult(ip="1.2.3.4", asn="AS15169", isp="Google", source="asn")
    provider.cache.set("asn:1.2.3.4", cached.model_dump())

    result = provider.enrich("1.2.3.4")
    assert result is not None
    assert result.asn == "AS15169"


def test_parse_date_valid():
    result = _parse_date("2025-01-15T10:00:00Z")
    assert result is not None
    assert result.year == 2025
    assert result.month == 1


def test_parse_date_none():
    assert _parse_date(None) is None


def test_parse_date_invalid():
    assert _parse_date("not-a-date") is None


def test_enrich_incident_with_malicious_hit():
    engine = EnrichmentEngine()
    abuse_result = ThreatIntelResult(
        ip="5.6.7.8", reputation="malicious", confidence=99.0, source="abuseipdb"
    )
    with patch.object(engine.providers[0], "enrich", return_value=abuse_result), \
         patch.object(engine.providers[1], "enrich", return_value=None), \
         patch.object(engine.providers[2], "enrich", return_value=None), \
         patch.object(engine.providers[3], "enrich", return_value=None):
        incident = {"source_ips": ["5.6.7.8"], "title": "Test"}
        result = engine.enrich_incident(incident)
        assert result["threat_intel_hit"] is True


def test_abuseipdb_no_api_key_logs_debug():
    provider = AbuseIPDBProvider()
    provider.cfg.abuseipdb_api_key = ""
    with patch("src.enrichment.engine.logger.debug") as mock_debug:
        result = provider.enrich("1.2.3.4")
        assert result is None
        mock_debug.assert_called_once_with("abuseipdb_api_key_not_configured")


def test_virustotal_no_api_key_logs_debug():
    provider = VirusTotalProvider()
    provider.cfg.virustotal_api_key = ""
    with patch("src.enrichment.engine.logger.debug") as mock_debug:
        result = provider.enrich("1.2.3.4")
        assert result is None
        mock_debug.assert_called_once_with("virustotal_api_key_not_configured")
