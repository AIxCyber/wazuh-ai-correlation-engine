
from prometheus_client import Counter, Gauge, Histogram

alerts_processed = Counter(
    "alerts_processed_total",
    "Total number of alerts processed",
    ["source", "status"],
)

incidents_generated = Counter(
    "incidents_generated_total",
    "Total number of incidents generated",
    ["severity"],
)

api_request_duration = Histogram(
    "api_request_duration_seconds",
    "API request duration in seconds",
    ["endpoint", "method", "status"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ai_processing_duration = Histogram(
    "ai_processing_duration_seconds",
    "AI analysis processing duration",
    ["provider"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

enrichment_lookup_duration = Histogram(
    "enrichment_lookup_duration_seconds",
    "Threat intel enrichment lookup duration",
    ["provider", "status"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

dlq_size = Gauge(
    "dlq_size",
    "Current number of records in dead-letter queue",
)

cache_hit_ratio = Gauge(
    "cache_hit_ratio",
    "Current cache hit ratio (0.0 to 1.0)",
)

active_incidents = Gauge(
    "active_incidents",
    "Number of currently active incidents",
    ["severity"],
)
