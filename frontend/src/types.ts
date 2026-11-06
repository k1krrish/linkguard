// Mirrors backend/app/schemas/models.py. Kept hand-written so students can read it.
export type CheckKind = "dns" | "tcp" | "http";
export type CheckStatus = "success" | "failure" | "unavailable" | "inconclusive";
export type FindingStatus = "issue" | "ok" | "inconclusive";
export type Severity = "info" | "low" | "medium";
export type Symptom = "dns_resolution_failure" | "connection_failure" | "http_error" | "slow_or_intermittent" | "unknown";
export type SourceKind = "live" | "pcap" | "both" | "sample";

export interface CheckResult {
  check: CheckKind;
  target: string;
  status: CheckStatus;
  started_at: string;
  elapsed_ms: number | null;
  error_kind: string | null;
  message: string;
  details: Record<string, unknown>;
  simulated: boolean;
}

export interface DnsInfo {
  id: number;
  is_response: boolean;
  qname: string | null;
  qtype: string | null;
  rcode: number | null;
  rcode_name: string | null;
  answer_count: number;
  answers: string[];
}
export interface LayerInfo { name: string; fields: Record<string, string | number | boolean | null> }

export interface PacketSummary {
  index: number;
  timestamp: number;
  rel_time: number;
  src: string | null;
  dst: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  ip_version: 4 | 6 | null;
  tcp_flags: string | null;
  info: string;
  markers: string[];
}
export interface PacketDetail extends PacketSummary {
  layers: LayerInfo[];
  dns: DnsInfo | null;
  tcp_seq: number | null;
  tcp_ack: number | null;
  tcp_window: number | null;
  tcp_payload_len: number | null;
  ttl: number | null;
}
export interface PacketPage { total: number; offset: number; limit: number; items: PacketSummary[] }

export interface DnsTransaction {
  id: string; qname: string; qtype: string; client: string; server: string; attempts: number;
  query_packets: number[]; response_packets: number[]; answered: boolean; rcode_name: string | null;
  responder: string | null; first_query_rel_time: number; seconds_before_capture_end: number;
}
export interface TcpFlow {
  id: string; client: string; server: string; packets: number; first_packet: number; last_packet: number;
  syn_count: number; syn_packets: number[]; syn_seen: boolean; synack_seen: boolean; handshake_observed: boolean;
  reset_packets: number[]; reset_context: string | null; retransmission_packets: number[]; outcome: string;
}
export interface TimelineEvent { packet: number; rel_time: number; kind: string; level: "info" | "notable" | "warning"; description: string }
export interface TimeBucket { start: number; packets: number; flagged: number }

export interface CaptureSummary {
  filename: string | null;
  file_format: "pcap" | "pcapng";
  file_size_bytes: number;
  total_packets: number;
  unparsed_packets: number;
  truncated: boolean;
  warnings: string[];
  first_timestamp: number | null;
  last_timestamp: number | null;
  duration_seconds: number;
  protocol_counts: Record<string, number>;
  ip_versions: Record<string, number>;
  top_endpoints: { endpoint: string; packets: number }[];
  dns_packets: number;
  tcp_packets: number;
  dns_transactions: DnsTransaction[];
  tcp_flows: TcpFlow[];
  events: TimelineEvent[];
  events_truncated: boolean;
  time_buckets: TimeBucket[];
  simulated: boolean;
}

export interface Evidence {
  id: string; kind: string; source: "live_check" | "pcap"; summary: string; observed_at: string | null;
  simulated: boolean; data: Record<string, unknown>; packet_refs: number[];
}
export interface Finding {
  rule_id: string; title: string; severity: Severity; status: FindingStatus; source: "live_check" | "pcap";
  observed: string; interpretation: string; limitations: string[]; alternatives: string[]; next_test: string;
  evidence_refs: string[]; packet_refs: number[]; simulated: boolean;
}
export interface ActivityEntry { at: string; kind: string; label: string; status: string | null; simulated: boolean }

export interface Investigation {
  id: string; title: string; symptom: Symptom; target: string | null; source: SourceKind;
  status: "awaiting_capture" | "completed" | "resolved"; simulated: boolean; sample_id: string | null;
  created_at: string; updated_at: string; checks: CheckResult[]; capture: CaptureSummary | null;
  evidence: Evidence[]; findings: Finding[]; next_actions: string[]; activity: ActivityEntry[];
}
export interface InvestigationListItem {
  id: string; title: string; symptom: Symptom; target: string | null; source: SourceKind;
  status: "awaiting_capture" | "completed" | "resolved"; simulated: boolean; sample_id?: string | null; created_at: string;
  issue_count: number; inconclusive_count: number; ok_count: number; packet_total: number | null;
}
export interface SampleInfo { id: string; title: string; description: string; teaches: string; symptom: Symptom; simulated: boolean }
export interface RuleInfo { rule_id: string; title: string; source: string; description: string; triggers: string; does_not_prove: string }
export interface Health {
  status: string; version: string; private_targets_allowed: boolean;
  limits: { max_upload_mb: number; max_packets: number; max_timeout_s: number };
}

export interface ReportTest { check: CheckKind; target: string; status: CheckStatus; elapsed_ms: number | null; message: string; simulated: boolean }
export interface Report {
  investigation_id: string; title: string; generated_at: string; symptom: Symptom; symptom_label: string;
  target: string | null; source: SourceKind; simulated: boolean; summary: string; status_counts: Record<FindingStatus, number>;
  test_outcomes: ReportTest[];
  packet_evidence: null | {
    filename: string | null; file_format: string; total_packets: number; duration_seconds: number;
    protocol_counts: Record<string, number>; dns_transactions: number; dns_unanswered: number; tcp_flows: number;
    tcp_flows_with_reset: number; tcp_retransmission_packets: number; notable_events: TimelineEvent[];
    warnings: string[]; simulated: boolean;
  };
  findings: Finding[]; evidence_index: Evidence[]; limitations: string[]; next_steps: string[];
}

export interface PacketFilters {
  protocol?: string; ip?: string; port?: string; flag?: string; marker?: string; q?: string; dns_name?: string;
}
