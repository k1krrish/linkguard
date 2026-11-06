# Test plan

Automated tests live in `backend/tests/`. Run `cd backend && pytest`. Live-network behavior is tested against a **local controlled server** and **patched resolvers**, never the public internet, so the suite is deterministic and works offline.

## 1. Automated backend tests

| File | Covers | Representative cases (expected outcome) |
|---|---|---|
| `test_validation.py` | SSRF guard | 127.0.0.1, 10.x, 192.168.x, 169.254.169.254, ::1, fe80::, multicast, `::ffff:127.0.0.1`, `localhost`, `*.local`, `*.internal` -> rejected; malformed names, URLs, paths, `@`, ports -> rejected; public domains/IPs -> accepted; private allowed only with the explicit setting |
| `test_diagnostics.py` | Live checks | TCP success; closed port -> `failure/connection_refused`; socket timeout -> `inconclusive`; ENETUNREACH -> `unavailable`; DNS success / NXDOMAIN (`failure`) / EAI_AGAIN (`unavailable`) / hung resolver bounded by timeout -> `inconclusive`; HTTP 200/302 -> success, 404 -> `http_4xx`, 503 -> `http_5xx`; redirects not followed; hostname resolving to 10.0.0.7 blocked |
| `test_pcap.py` | Analyzer | pcap and pcapng parse equally; totals and protocol counts; DNS matching (answered, unanswered, wrong ID, response before query, NXDOMAIN); reset context classification; conservative retransmissions (plain ACKs not flagged); mid-stream capture not labelled a handshake failure; IPv6; ARP/ICMP/fragment/unknown/non-IP frames; no payload bytes in output; empty, garbage and truncated files; size limit; packet limit |
| `test_rules.py` | Every rule | Per rule: positive, negative, inconclusive where meaningful (DNS-001/002, TCP-001/002/003, EVID-001, CAP-001, LIVE-DNS/TCP/HTTP); engine ordering, unique IDs, crash isolation; every finding has required fields and avoids overclaiming phrases |
| `test_api.py` | REST API | Health, rules, samples; OpenAPI paths; check endpoints and the shared error shape; sample scenarios produce expected findings and are labelled simulated; investigation validation; offline live investigation yields only `inconclusive` findings; upload, filters, pagination, packet detail; malformed/oversized/empty uploads; filename sanitizing; JSON/CSV reports from real data; CSV formula neutralization; delete; store bound |

## 2. Frontend checks

```bash
cd frontend
npm run typecheck     # tsc --noEmit, strict
npm run build         # tsc -b && vite build
```

## 3. Manual / browser test procedure

Start both servers (README), then verify. A scripted run of these steps with Playwright passed 20/20 checks during development (not part of the repository).

| # | Step | Expected |
|---|---|---|
| 1 | Open `/` with an empty server | First-run guide, API pill says online, sample cards visible |
| 2 | Load **DNS queries that get no answer** | Investigation opens with a Simulated banner; DNS-001 *Needs attention*, expanded, with limitations and next test |
| 3 | Click a packet reference (#1) | Packet explorer opens with packet 1 selected |
| 4 | Search `unreachable` | 3 matches; detail panel shows DNS layers |
| 5 | Search a nonsense string | "No packets match these filters" with a clear-filters action |
| 6 | Load **TCP refused**, **HTTP 503**, **Insufficient** | TCP-001 + LIVE-TCP-001; LIVE-HTTP-001 saying not necessarily a network failure; EVID-001 *Inconclusive* |
| 7 | Reports > open one > JSON and CSV | Files download; contents match the on-screen report |
| 8 | New investigation > Packet capture, upload `tcp_retransmission.pcap` | TCP-002 and TCP-003 appear |
| 9 | New investigation with target `127.0.0.1` | Visible error "not a public address"; nothing created |
| 10 | On an investigation without a capture, upload `malformed.pcap` | Error "not a PCAP or PCAPNG capture"; investigation unchanged |
| 11 | Live checks > DNS for a public domain | A real status appears (success with internet; otherwise failure/unavailable, never invented) |
| 12 | Live checks > TCP to `10.0.0.1` | Rejected with a visible error |
| 13 | Stop the backend and reload | "Cannot reach the LinkGuard backend" error state with retry |
| 14 | Narrow the window to phone width | Hamburger menu, no horizontal page scroll |

## 4. Fixtures (`backend/tests/fixtures/`, synthetic)

| File | Expected analysis |
|---|---|
| `dns_unanswered.pcap` | 9 packets; DNS-001 issue (3 attempts); one other name answered |
| `dns_answered.pcap` | DNS-001 reports all answered; CAP-001 ok |
| `dns_nxdomain.pcap` | DNS-002 low-priority issue |
| `tcp_refused.pcap` | TCP-001: SYN answered by RST/ACK on port 8081; handshake on 443 fine |
| `tcp_retransmission.pcap` | TCP-002 (2 data + 2 SYN repeats), TCP-003 (SYNs, no reply observed) |
| `tcp_midstream_rst.pcap` | TCP-001 low priority; no retransmissions flagged for repeated plain ACKs |
| `insufficient.pcap` | 3 packets; EVID-001 and DNS-001 inconclusive |
| `ipv6_dns_unanswered.pcap` | IPv6 variant; DNS-001 |
| `mixed_layers.pcap` | ARP, ICMP, fragment, unknown protocol, non-IP frame; no crash |
| `tcp_refused.pcapng` | Same as `tcp_refused.pcap` in pcapng format |
| `empty.pcap`, `truncated.pcap`, `malformed.pcap` | Zero packets / truncation warning / rejected with `not_a_capture` |

Regenerate with `python backend/scripts/generate_fixtures.py`.

## 5. Not tested / known gaps

- Live checks against the real internet are not part of the automated suite (non-deterministic).
- No load or performance testing; no performance figures are claimed.
- No automated frontend unit tests; the browser steps above are manual (a one-off Playwright script was used during development).
- Real-world captures (large, NAT'd, VLAN-tagged, tunnelled) were not tried.
