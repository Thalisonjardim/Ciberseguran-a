# Network Traffic Analysis — Home Network Baseline

**Case ID:** NTA-001 | **Date:** November 2026 | **Category:** Blue Team / SOC Level 1

## Executive summary

This learning project examines a real packet capture from a personal network. Its purpose is to establish a small traffic baseline, practice packet inspection and distinguish observable events from hypotheses. No attack was confirmed within the limited observation window.

The capture was collected by the author and the initial analysis and documentation were assisted by AI. The original PCAPNG was checked programmatically; the Wireshark filters below provide a manual validation workflow.

## Capture overview

- Environment: personal network, macOS.
- Format: PCAPNG.
- Duration: approximately 25.32 seconds.
- Total: 326 frames.

| Protocol | Frames |
|---|---:|
| TCP | 206 |
| UDP | 89 |
| ARP | 24 |
| ICMPv6 | 7 |

At the network layer, 240 frames carried IPv6 and 62 carried IPv4; the remaining 24 were ARP. These counts describe different protocol layers and should not be added together.

The unfiltered Wireshark Protocol Hierarchy additionally identifies 22 QUIC frames, 65 TLS frames, 27 DNS frames and 7 mDNS frames. Total captured frame bytes: 93,606.

## Methodology

1. Inspect Statistics > Protocol Hierarchy, Endpoints and Conversations.
2. Isolate ARP, DNS, TCP and ICMPv6 traffic using display filters.
3. Correlate requests and responses using frame numbers, transaction IDs and transport ports.
4. Separate observed facts, possible explanations and follow-up actions.

## Evidence and findings

### 1. ARP and local discovery

Frames 42 and 43 show an ARP request and reply. Host A asked for the MAC address associated with Host B's IPv4 address; Host B replied. Multiple ARP requests from Host A to different local addresses warrant contextual review.

Filter: `arp` or `frame.number == 42 || frame.number == 43`.

**Assessment:** compatible with local device discovery. Repeated ARP requests alone do not prove scanning with malicious intent or ARP spoofing.

### 2. DNS resolution

Frames 88, 89 and 90 contain HTTPS (type 65), AAAA and A queries for chatgpt.com. Frames 103, 99 and 100 respectively contain their responses.

Frame 100 contains:

| Field | Value |
|---|---|
| Transaction ID | 0x84a1 |
| Query type | A |
| Answer count | 2 |
| TTL | 217 seconds |
| IPv4 answer 1 | 104.18.32.47 |
| IPv4 answer 2 | 172.64.155.209 |

The Wireshark DNS screenshot links response frame 100 to request frame 90 and reports a response time of 5.436 ms. The DNS transport itself used IPv6. An IPv6 DNS transport can resolve IPv4 addresses.

Filter: `dns.qry.name == "chatgpt.com" && dns.flags.response == 1 && dns.qry.type == 1`.

To inspect possible subsequent traffic: `ip.addr == 104.18.32.47 || ip.addr == 172.64.155.209`. Also inspect the AAAA answers and IPv6 conversations.

**Assessment:** DNS resolution is not proof of a human visiting a website. Background applications and shared hosting can complicate attribution.

### 3. TCP connection establishment

Frames 1, 3 and 4 contain a SYN, SYN-ACK and ACK sequence between client port 63042 and remote port 443. The initial exchange also includes ECN negotiation flags. The ACK in frame 4 occurs at 0.084723 s. Frame 6 shows a TLS Client Hello with an iCloud service hostname. This stream is not evidence of a ChatGPT connection. Frames 10 and 11 are flagged as previous segment not captured and out-of-order respectively; these flags alone do not establish malicious activity.

Filter: `tcp.port == 63042`.

**Assessment:** the three-way handshake completed. Port 443 suggests HTTPS-related traffic but does not identify an application by itself. Inspect TLS Client Hello and SNI where available using `tls.handshake.extensions_server_name`.

### 4. UDP and service discovery

The capture contains 54 UDP frames involving port 443, consistent with possible QUIC traffic, and seven involving port 5353.

Frames 143 and 144 contain mDNS queries for SMB, RFB, AFP and ADISK services.

Filters: `udp.port == 443`, `quic`, `udp.port == 5353`.

**Assessment:** service discovery does not establish that these services are enabled or vulnerable. UDP/443 alone does not prove QUIC or HTTP/3.

### 5. ICMPv6 operational event

Frame 104 contains ICMPv6 Type 1, Code 4 (Destination Unreachable / Port Unreachable), following a DNS response. A closed UDP socket is a plausible explanation, not a confirmed root cause.

Filter: `icmpv6.type == 1 && icmpv6.code == 4`.

## Manual evidence validation

Six screenshots were collected in Wireshark: unfiltered protocol hierarchy, DNS response, TCP handshake, ARP, mDNS and frame 104. Screenshots were redacted offline to remove network identifiers and raw packet bytes. The image files are pending upload. The frame 104 screenshot shows the protocol stack and ICMP error coloring rule; a further screenshot expanding ICMPv6 Type and Code would make the error evidence clearer.

## SOC triage conclusion

| Finding | Disposition |
|---|---|
| DNS resolution | Consistent with routine activity |
| TCP handshake | Established connection |
| Repeated ARP requests | Identify originating device before escalation |
| mDNS queries | Compatible with service discovery |
| ICMPv6 error | Operational event; investigate if recurrent |

No confirmed indicator of compromise was established. This is a baseline exercise, not a malware investigation or a comprehensive security assessment.

## Limitations and next steps

- The short capture cannot establish long-term behavior or rule out compromise.
- The raw capture, local addresses, MAC addresses and private IPv6 addresses are intentionally withheld for privacy.
- Application classification requires validation in Wireshark; TShark was not available for the programmatic review.
- Add redacted Wireshark screenshots after manual verification, correlate DNS answers with actual connections, and repeat the exercise using controlled benign and simulated suspicious traffic in an isolated lab.

## Resumo em português

Estudo de análise de tráfego real de uma rede pessoal, com 326 pacotes e duração aproximada de 25,32 segundos. Foram investigados ARP, DNS, estabelecimento de conexões TCP, descoberta de serviços via mDNS e um erro ICMPv6. O objetivo é demonstrar metodologia de triagem SOC N1, interpretação de evidências e distinção entre fatos e hipóteses. Nenhum ataque foi confirmado. A captura original não foi publicada por privacidade.
