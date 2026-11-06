# Viva preparation

Short, accurate answers. "In our project" ties each concept to the code.

## Project and method

**1. What problem does LinkGuard solve?**
It helps a student or admin investigate a network symptom systematically: gather evidence (live checks, packet capture), apply explicit rules, and report findings with their limits, instead of guessing.

**2. Which syllabus topics does it cover?**
TCP/IP model, application-layer protocols (DNS, HTTP/HTTPS), transport layer (TCP handshake, flags, reset, retransmission), network layer (IPv4/IPv6, TTL, fragments, ICMP) and packet analysis. It does not cover all of CSE3003 (e.g. routing algorithms, wireless, security mechanisms).

**3. Why does it never say "the network is down"?**
One failed check is one observation from one host at one moment. Many causes can produce the same symptom, so the tool reports the observation, possible explanations and the next test.

**4. What is the difference between evidence and a finding?**
Evidence is a normalized observation (e.g. "3 DNS queries for X, no response observed"). A finding is a rule's interpretation of evidence, with limitations and a next test.

**5. Why no confidence score?**
We have no statistical model that justifies a number, so a percentage would be fabricated precision. We use status (issue / inconclusive / ok) and priority instead.

## DNS

**6. How does DNS resolution work?**
A stub resolver on the host asks a recursive resolver (usually UDP port 53). The resolver consults its cache or walks root, TLD and authoritative servers, then returns the answer. Our live check uses the host's system resolver.

**7. What does an unanswered DNS query in a capture mean?**
Only that no matching response was observed in that capture. The resolver may be down, but the query or response may also have been dropped, filtered, or missed by the capture point, or the capture may have ended early (rule DNS-001 lists these).

**8. How do you match a DNS response to a query?**
Same client IP/port, same 16-bit DNS ID, same name and type, and the response comes later. See `_Analyzer._dns`.

**9. NXDOMAIN vs SERVFAIL vs REFUSED?**
NXDOMAIN: the name does not exist. SERVFAIL: the resolver could not complete the lookup. REFUSED: the server declined (policy). All three are *responses*, so the resolver was reachable (rule DNS-002).

**10. UDP or TCP for DNS?**
UDP by default; TCP for large responses, zone transfers, or after truncation (TC bit). We decode DNS over TCP only for complete single-segment messages.

## TCP / IP

**11. Explain the three-way handshake.**
Client sends SYN (seq x); server replies SYN/ACK (seq y, ack x+1); client sends ACK (ack y+1). We mark a handshake "observed" only if all three appear.

**12. What does a RST after a SYN mean?**
The destination (or a device acting for it, such as a firewall) rejected the attempt. A closed port typically behaves this way, but the reset does not uniquely identify the cause or sender (rule TCP-001).

**13. Connection refused vs timeout?**
Refused: an explicit RST came back (a host answered). Timeout: silence, which may be a silent drop, a down host, or loss. That is why a timeout is *inconclusive* in our tool, while refused is a definite *failure* of that attempt.

**14. How do you detect retransmissions, and why is it conservative?**
Same direction, same sequence number and same payload length seen again (or a repeated SYN). Duplicate ACKs and partial overlaps are not flagged, so absence of a flag does not prove no loss. Retransmissions do not prove congestion: loss, delayed ACKs or capture duplicates also cause them.

**15. How does TCP retransmit?**
A sender keeps unacknowledged data and resends it when a retransmission timer (RTO) expires or after duplicate ACKs (fast retransmit). RTO typically backs off exponentially, which is why repeated SYNs in our fixture are spaced 1 s then 2 s.

**16. What are TCP flags?**
Control bits: SYN (open), ACK (acknowledges), FIN (graceful close), RST (abort), PSH (push data), URG, ECE, CWR. See `_TCP_BITS` in `pcap.py`.

**17. IPv4 vs IPv6 in your analyzer?**
We read source/destination, TTL (IPv4) or hop limit (IPv6) and the transport header; IPv6 extension headers are skipped. Non-first IPv4 fragments are listed but not decoded, since they have no transport header.

**18. Why compute TCP payload length from header fields?**
Ethernet pads short frames, so counting bytes after the TCP header could invent payload. IP total length minus IP and TCP header lengths is exact.

## HTTP / HTTPS

**19. What do 4xx and 5xx mean for diagnosis?**
The server answered, so DNS, TCP (and TLS) worked. 4xx: the request was rejected/not found. 5xx: server-side error. Neither alone shows a network failure (rule LIVE-HTTP-001).

**20. Why don't you follow redirects?**
A redirect can point at an internal address (SSRF). We report the 3xx status and do not follow it.

**21. What happens on a TLS certificate error?**
The handshake fails before any HTTP exchange; we report *failure: tls_verification_failed* and point to the certificate or name, not connectivity. We never disable verification.

## Security and engineering

**22. What is SSRF and how do you prevent it?**
Server-side request forgery: tricking the server into probing internal systems. We allow only public IPs/domains, block loopback/private/link-local/multicast/reserved ranges, resolve names once and check *every* returned address (blocks DNS rebinding), connect to the validated IP, allow-list ports, and don't follow redirects.

**23. How do you handle untrusted PCAP uploads?**
Magic-byte check, size limit enforced while streaming, packet and time limits, in-memory parsing, per-packet error isolation, and no payload retention. A malformed file yields a safe error.

**24. Why is the store in memory?**
The brief excludes a database to keep the MVP focused. The cost is that investigations are lost on restart (documented limitation).

**25. How is the rule engine testable?**
Rules are pure functions of `Evidence`. Tests build small synthetic captures and assert positive, negative and inconclusive outcomes, and a wording test checks that findings avoid overclaiming phrases.

## Tools

**26. How does this relate to Wireshark / tcpdump?**
Those capture and display packets; LinkGuard parses an existing capture with Scapy and adds rule-based, limitation-aware interpretation. It does not capture live traffic.

**27. What would you add with more time?**
Persistent storage, live capture, TLS/QUIC analysis, RTT estimation, PDF export, and code-splitting the frontend.
