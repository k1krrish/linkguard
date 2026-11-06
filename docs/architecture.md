# Architecture and data flow

## Layers

1. **Frontend** (`frontend/src`): React pages call a typed API client (`api.ts`). The UI contains no diagnostic logic; it only displays what the backend returns.
2. **API** (`backend/app/api/routes.py`): thin FastAPI handlers. Input is validated by Pydantic models; domain errors become one JSON shape: `{"error": {"code", "message", "details?"}}`.
3. **Services** (`backend/app/services`): the real work.
   - `validation.py` - decides whether a target may be probed (SSRF guard).
   - `diagnostics.py` - DNS, TCP and HTTP(S) checks.
   - `pcap.py` - Scapy analyzer.
   - `evidence.py` - converts results to normalized `Evidence`.
   - `investigations.py` - orchestrates checks, capture and rules; an in-memory store (inside the same module) keeps results.
   - `reports.py` - builds `Report`, exports JSON/CSV.
4. **Rule engine** (`backend/app/rules`): reads `Evidence`, returns `Finding`s.

## Core data model (`schemas/models.py`)

| Model | Meaning |
|---|---|
| `CheckResult` | One live check: `status` is `success`, `failure`, `unavailable` or `inconclusive` |
| `CaptureSummary` | Parsed capture: totals, protocol counts, DNS transactions, TCP flows, events, time buckets |
| `Evidence` | A normalized observation with an ID (`E-DNS-D1`), source, summary and packet references |
| `Finding` | A rule's conclusion: `rule_id`, title, `status` (issue / ok / inconclusive), priority, observed, interpretation, limitations, alternatives, `next_test`, evidence + packet refs |
| `Investigation` | Checks + capture + evidence + findings + activity timeline |
| `Report` | A view of an investigation for reading and export |

Status meanings for checks: **failure** = the remote side gave a definite negative answer (refused, name not found, HTTP 5xx);
**inconclusive** = no answer in time; **unavailable** = this host could not perform the check (no route, resolver unreachable).

## Flow 1: live investigation

```
POST /api/investigations {symptom, target, source: "live", live: {...}}
  validate_create()                      reject bad target/port (422)
  _run_live_checks()                     DNS + TCP ports + HTTP in parallel threads
      parse_host / check_tcp_port        SSRF guard
      resolve once -> verify every address is public -> connect to that IP
  build_evidence(checks)                 CheckResult -> Evidence (E-CHK-n)
  run_rules(context)                     LIVE-DNS-001, LIVE-TCP-001, LIVE-HTTP-001
  investigations.store.add(entry)              -> 201 Investigation
```

## Flow 2: capture analysis

```
POST /api/investigations/{id}/capture   multipart upload
  read in 1 MB chunks, stop at the size limit (413)
  detect_format()                        magic bytes: pcap / pcapng, else 422
  analyze_capture()                      Scapy PcapReader over BytesIO (nothing written to disk)
      _dissect() per packet              metadata only; payload bytes dropped
      _Analyzer.feed()                   DNS transaction table, TCP flow table, events, markers
  build_evidence(parsed)                 unanswered queries, DNS errors, resets, repeats, SYN w/o reply
  run_rules()                            DNS-001/002, TCP-001/002/003, EVID-001, CAP-001
  store.add(entry)               packet metadata kept for the explorer
```

## Packet explorer

`GET /investigations/{id}/packets?q=&protocol=&ip=&port=&flag=&marker=&offset=&limit=` filters the stored
`PacketDetail` list and returns light `PacketSummary` rows. `GET .../packets/{n}` returns decoded layers for one packet.
Full packet bytes are never sent.

## Rule engine

A rule is a class with `rule_id`, `title`, `source`, documentation strings, and `evaluate(ctx) -> list[Finding]`.
`run_rules` calls every rule; a rule that raises becomes an *inconclusive* finding instead of crashing the request.
Findings are sorted: issues, then inconclusive, then ok; within each by priority.

| Rule | Source | Reads evidence kind |
|---|---|---|
| LIVE-DNS-001 / LIVE-TCP-001 / LIVE-HTTP-001 | live | `dns_check`, `tcp_check`, `http_check` |
| DNS-001 | pcap | `dns_unanswered_query` (or reports all answered) |
| DNS-002 | pcap | `dns_error_response` |
| TCP-001 | pcap | `tcp_reset` |
| TCP-002 | pcap | `tcp_retransmission` |
| TCP-003 | pcap | `tcp_syn_no_reply` |
| EVID-001 | pcap | capture too small / empty / truncated / no DNS-TCP |
| CAP-001 | pcap | adequate capture with no anomaly indicators |

To add a rule: subclass `Rule`, implement `evaluate`, append it to `RULES` in `engine.py`, and add positive, negative and inconclusive tests.

## Key analyzer decisions

- **DNS matching key**: client IP + client port + DNS ID + lower-cased name + type; a response must come after its query. A query is "unanswered" only if no such response appears *in the capture*.
- **End-of-capture grace**: if every unanswered query is within 2 s of the capture end, DNS-001 is *inconclusive* (the capture may have stopped early).
- **Reset context**: SYN answered by RST / reset after handshake / no handshake in capture / reset by initiator before SYN-ACK.
- **Retransmission indicator**: same direction + same sequence number + same non-zero payload length (or same SYN seq). Plain repeated ACKs are not counted.
- **Payload length** is computed from IP and TCP header fields, so Ethernet padding cannot create false repeats.

## Security boundaries

Validation happens in the service layer so every entry point (single checks and investigations) shares it. See the README "Safety design" section.
