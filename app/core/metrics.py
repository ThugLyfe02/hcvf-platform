from prometheus_client import Counter, Histogram

CAMPAIGNS_CREATED = Counter(
    "hcvf_campaigns_created_total",
    "Total campaigns created",
)
CAMPAIGNS_COMPLETED = Counter(
    "hcvf_campaigns_completed_total",
    "Total campaigns completed",
)
FINDINGS_DETECTED = Counter(
    "hcvf_findings_detected_total",
    "Total findings detected",
)
TASK_DURATION = Histogram(
    "hcvf_task_duration_seconds",
    "Campaign task execution duration in seconds",
)
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
