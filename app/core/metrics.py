from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Counter(
    "hcvf_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_REQUEST_DURATION = Histogram(
    "hcvf_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)
CAMPAIGN_RUNS = Counter(
    "hcvf_campaign_runs_total",
    "Campaign execution attempts",
    ["status"],
)
