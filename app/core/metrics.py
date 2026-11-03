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
HUNTS_STARTED = Counter(
    "hcvf_hunts_started_total",
    "Agentic hunts started",
)
HUNTS_FINISHED = Counter(
    "hcvf_hunts_finished_total",
    "Agentic hunts finished, by outcome",
    ["outcome"],
)
PROBES_EXECUTED = Counter(
    "hcvf_probes_executed_total",
    "Probe executions, by probe and status",
    ["probe", "status"],
)
FINDINGS_BY_SEVERITY = Counter(
    "hcvf_findings_total",
    "Findings emitted, by severity",
    ["severity"],
)
HUNT_REQUESTS = Histogram(
    "hcvf_hunt_requests",
    "Outbound requests per hunt",
    buckets=(5, 10, 25, 50, 100, 200, 400, 800),
)

SUPPRESSED_FINDINGS = Counter(
    "hcvf_findings_suppressed_total",
    "Findings dropped by an accepted suppression rule",
)
