"""Pydantic models shared by the API, services and rule engine.

Three ideas carry the whole design (worth knowing for the viva):

* ``CheckResult``  - the outcome of ONE live DNS / TCP / HTTP check.
* ``Evidence``     - a normalized observation (from a live check or a capture).
                     Rules only ever read Evidence, never raw packets.
* ``Finding``      - what a rule concluded, with limits and a next test.
"""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


CheckKind = Literal["dns", "tcp", "http"]
CheckStatus = Literal["success", "failure", "unavailable", "inconclusive"]
Severity = Literal["info", "low", "medium"]
FindingStatus = Literal["issue", "ok", "inconclusive"]
Symptom = Literal[
    "dns_resolution_failure",
    "connection_failure",
    "http_error",
    "slow_or_intermittent",
    "unknown",
]
SourceKind = Literal["live", "pcap", "both", "sample"]
InvestigationStatus = Literal["awaiting_capture", "completed", "resolved"]


# --------------------------------------------------------------------------
# Live checks
# --------------------------------------------------------------------------
class DnsCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253, description="Domain name to resolve")
    record_type: Literal["A", "AAAA", "BOTH"] = "A"
    timeout: float = Field(default=5.0, gt=0, le=10, description="Seconds (max 10)")


class TcpCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253, description="Public domain or IP")
    port: int = Field(ge=1, le=65535)
    timeout: float = Field(default=5.0, gt=0, le=10)


class HttpCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, description="http:// or https:// URL")
    method: Literal["GET", "HEAD"] = "GET"
    timeout: float = Field(default=5.0, gt=0, le=10)


class CheckResult(BaseModel):
    check: CheckKind
    target: str
    status: CheckStatus
    started_at: datetime
    elapsed_ms: Optional[float] = None
    error_kind: Optional[str] = None
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    simulated: bool = False


# --------------------------------------------------------------------------
# Packet capture
# --------------------------------------------------------------------------
class DnsInfo(BaseModel):
    id: int
    is_response: bool
    qname: Optional[str] = None
    qtype: Optional[str] = None
    rcode: Optional[int] = None
    rcode_name: Optional[str] = None
    answer_count: int = 0
    answers: list[str] = Field(default_factory=list)


class LayerInfo(BaseModel):
    name: str
    fields: dict[str, Any] = Field(default_factory=dict)


class PacketSummary(BaseModel):
    index: int = Field(description="1-based position in the capture")
    timestamp: float
    rel_time: float = Field(description="Seconds since first packet")
    src: Optional[str] = None
    dst: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    ip_version: Optional[Literal[4, 6]] = None
    tcp_flags: Optional[str] = None
    info: str = ""
    markers: list[str] = Field(default_factory=list)


class PacketDetail(PacketSummary):
    layers: list[LayerInfo] = Field(default_factory=list)
    dns: Optional[DnsInfo] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None
    tcp_payload_len: Optional[int] = None
    ttl: Optional[int] = None


class PacketPage(BaseModel):
    total: int
    offset: int
    limit: int
    items: list[PacketSummary]


class DnsTransaction(BaseModel):
    id: str
    qname: str
    qtype: str
    client: str
    server: str
    attempts: int
    query_packets: list[int]
    response_packets: list[int] = Field(default_factory=list)
    answered: bool
    rcode_name: Optional[str] = None
    responder: Optional[str] = None
    first_query_rel_time: float
    seconds_before_capture_end: float


class TcpFlow(BaseModel):
    id: str
    client: str
    server: str
    packets: int
    first_packet: int
    last_packet: int
    syn_count: int
    syn_packets: list[int] = Field(default_factory=list)
    syn_seen: bool
    synack_seen: bool
    handshake_observed: bool
    reset_packets: list[int] = Field(default_factory=list)
    reset_context: Optional[str] = None
    retransmission_packets: list[int] = Field(default_factory=list)
    outcome: str


class TimelineEvent(BaseModel):
    packet: int
    rel_time: float
    kind: str
    level: Literal["info", "notable", "warning"] = "info"
    description: str


class EndpointCount(BaseModel):
    endpoint: str
    packets: int


class TimeBucket(BaseModel):
    start: float = Field(description="Seconds since first packet")
    packets: int
    flagged: int = Field(description="Packets carrying an anomaly marker (reset, retransmission, unanswered DNS...)")


class CaptureSummary(BaseModel):
    filename: Optional[str] = None
    file_format: Literal["pcap", "pcapng"]
    file_size_bytes: int
    total_packets: int
    unparsed_packets: int = 0
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    duration_seconds: float = 0.0
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    ip_versions: dict[str, int] = Field(default_factory=dict)
    top_endpoints: list[EndpointCount] = Field(default_factory=list)
    dns_packets: int = 0
    tcp_packets: int = 0
    dns_transactions: list[DnsTransaction] = Field(default_factory=list)
    tcp_flows: list[TcpFlow] = Field(default_factory=list)
    events: list[TimelineEvent] = Field(default_factory=list)
    events_truncated: bool = False
    time_buckets: list[TimeBucket] = Field(default_factory=list)
    simulated: bool = False


# --------------------------------------------------------------------------
# Evidence and findings
# --------------------------------------------------------------------------
class Evidence(BaseModel):
    id: str
    kind: str
    source: Literal["live_check", "pcap"]
    summary: str
    observed_at: Optional[datetime] = None
    simulated: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
    packet_refs: list[int] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatus
    source: Literal["live_check", "pcap"]
    observed: str
    interpretation: str
    limitations: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    next_test: str
    evidence_refs: list[str] = Field(default_factory=list)
    packet_refs: list[int] = Field(default_factory=list)
    simulated: bool = False


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    source: Literal["live_check", "pcap"]
    description: str
    triggers: str
    does_not_prove: str


# --------------------------------------------------------------------------
# Investigations
# --------------------------------------------------------------------------
class LiveChecksPlan(BaseModel):
    dns: bool = True
    tcp_ports: list[int] = Field(default_factory=lambda: [443], max_length=3)
    http: bool = True
    http_scheme: Literal["http", "https"] = "https"
    timeout: float = Field(default=5.0, gt=0, le=10)


class InvestigationCreate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=120)
    symptom: Symptom = "unknown"
    target: Optional[str] = Field(default=None, max_length=253)
    source: Literal["live", "pcap", "both"] = "live"
    live: LiveChecksPlan = Field(default_factory=LiveChecksPlan)


class ActivityEntry(BaseModel):
    at: datetime
    kind: Literal["created", "check", "capture", "rules", "sample"]
    label: str
    status: Optional[str] = None
    simulated: bool = False


class Investigation(BaseModel):
    id: str
    title: str
    symptom: Symptom
    target: Optional[str] = None
    source: SourceKind
    status: InvestigationStatus
    simulated: bool = False
    sample_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    checks: list[CheckResult] = Field(default_factory=list)
    capture: Optional[CaptureSummary] = None
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    activity: list[ActivityEntry] = Field(default_factory=list)


class InvestigationListItem(BaseModel):
    id: str
    title: str
    symptom: Symptom
    target: Optional[str] = None
    source: SourceKind
    status: InvestigationStatus
    simulated: bool
    sample_id: Optional[str] = None
    created_at: datetime
    issue_count: int
    inconclusive_count: int
    ok_count: int
    packet_total: Optional[int] = None


class SampleInfo(BaseModel):
    id: str
    title: str
    description: str
    teaches: str
    symptom: Symptom
    simulated: bool = True


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
class ReportTest(BaseModel):
    check: CheckKind
    target: str
    status: CheckStatus
    elapsed_ms: Optional[float] = None
    message: str
    simulated: bool = False


class ReportCapture(BaseModel):
    filename: Optional[str] = None
    file_format: str
    total_packets: int
    duration_seconds: float
    protocol_counts: dict[str, int]
    dns_transactions: int
    dns_unanswered: int
    tcp_flows: int
    tcp_flows_with_reset: int
    tcp_retransmission_packets: int
    notable_events: list[TimelineEvent]
    warnings: list[str]
    simulated: bool


class Report(BaseModel):
    investigation_id: str
    title: str
    generated_at: datetime
    symptom: Symptom
    symptom_label: str
    target: Optional[str] = None
    source: SourceKind
    simulated: bool
    summary: str
    status_counts: dict[str, int]
    test_outcomes: list[ReportTest]
    packet_evidence: Optional[ReportCapture] = None
    findings: list[Finding]
    evidence_index: list[Evidence]
    limitations: list[str]
    next_steps: list[str]
