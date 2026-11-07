# Network Traffic Analysis & Threat Hunting

**Reproducible synthetic PCAP exercise · 18 focused tests**

A standard-library Python script generates a classic Ethernet/IPv4 PCAP containing **20 fabricated packets**. A bounded offline analyzer decodes DNS/HTTP observations and produces two **triage candidates**, not confirmed malicious behavior.

![Synthetic PCAP analysis overview](https://raw.githubusercontent.com/IXI-2773/Cybersecurity_Portfolio/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/pcap-evidence-overview.svg)

| Rule | Fabricated result |
| --- | --- |
| DNS NXDOMAIN cluster | Four matching NXDOMAIN replies in 36 seconds |
| HTTP POST review | POST to `collector.invalid/upload` |
| Benign comparisons | Normal DNS reply and HTTP GET |

![Synthetic DNS NXDOMAIN review](https://raw.githubusercontent.com/IXI-2773/Cybersecurity_Portfolio/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/dns-nxdomain-investigation.svg)

![Synthetic HTTP GET/POST comparison](https://raw.githubusercontent.com/IXI-2773/Cybersecurity_Portfolio/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/http-request-comparison.svg)

These are offline **illustrations**, not Wireshark screenshots. The [source-linked analyst report](03-network-pcap/CASE_REPORT.md) identifies packet frames **1–20**, exact trigger times, controls and a proportionate synthetic-only disposition. Manual Wireshark inspection has not been performed.

[Generator and analyzer](03-network-pcap/README.md) · [Simulated network case report](03-network-pcap/CASE_REPORT.md) · [All case studies](CASE_STUDIES.md)

**Live designed page:** https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/network-traffic-analysis.html
