# LAB-NET-001 — DNS and HTTP Packet Triage

**Analyst:** Don Lopez · **Classification:** Synthetic network investigation; **no real incident**  
**Evidence:** [Deterministically generated classic PCAP](generate_fixture.py) · [offline decoder and predicates](analyze_pcap.py) · [frozen expected output](expected_findings.json)  
**Scope:** 20 invented Ethernet/IPv4 packets; 12 decoded DNS/HTTP message events · **Finding count:** 2  
**Disposition:** `SYNTHETIC_REVIEW_ONLY` — neither a confirmed C2 channel nor data theft

## 30-second analyst summary

A fabricated client `192.0.2.10` generates four DNS A queries answered with NXDOMAIN within 36.2 seconds, followed later by an HTTP POST addressed to `collector.invalid/upload`. The offline rule engine identifies **two review candidates**: `NET_DNS_NXDOMAIN_BURST` at **12:00:36.200 UTC** and `NET_HTTP_POST_RESERVED_HOST` at **12:01:15.030 UTC** on October 10, 2026. A second client provides normal DNS/HTTP controls. These events were **constructed**, not captured from a device.

## Source-attributed packet timeline

The frame positions below follow [`build_capture()`](generate_fixture.py), which sorts its generated packets by timestamp. They can be checked in the binary regenerated from that script.

| UTC time (Oct 10, 2026) | Generated frame(s) | Evidence and source | Rule interpretation |
| --- | --- | --- | --- |
| 12:00:00.000–12:00:36.200 | **1–8** | Four A questions `bad-1.invalid` … `bad-4.invalid` from `192.0.2.10` to `198.51.100.53`, paired to resolver NXDOMAIN replies | Fourth reply at 12:00:36.200 completes **four matched errors within 60 seconds** |
| 12:00:48.000–12:00:48.200 | **9–10** | `192.0.2.11` queries `portal.example`; receives a normal DNS answer | Benign control; no alert |
| 12:01:00.000–12:01:00.040 | **11–15** | `192.0.2.11` performs synthetic TCP handshake, HTTP GET `/index.html`, 200 response | Benign HTTP control; no alert |
| 12:01:15.000–12:01:15.040 | **16–20** | `192.0.2.10` performs synthetic TCP handshake, POST `/upload`, `Host: collector.invalid`, body `SAFE`, fabricated 200 response | **POST request at frame 19, 12:01:15.030** matches reserved-host rule |

Addresses come from documentation-only ranges; the `.invalid` and `.example` names are reserved. The packet set is **made by code without network transmission**, and the fake response is not proof of contact with a web service.

## Exact detector conditions and result provenance

| Finding ID | Rule predicate | Observed synthetic result | Alternative explanations |
| --- | --- | --- | --- |
| `NET_DNS_NXDOMAIN_BURST` | Matched DNS question/response, NXDOMAIN (rcode 3), **at least four** responses for the same client within **60 seconds** | `192.0.2.10`; four responses; alert at `2026-10-10T12:00:36.200Z` | Misconfiguration, typos, application retries, stale domain discovery |
| `NET_HTTP_POST_RESERVED_HOST` | Unencrypted HTTP request, method **POST**, `Host` ending in **.invalid** | `192.0.2.10` → `203.0.113.80:80`, `collector.invalid/upload` at `2026-10-10T12:01:15.030Z` | Artificial hostname by construction; normal apps regularly POST |

[See exact JSON oracle](expected_findings.json) and [rule implementation](analyze_pcap.py). Hypotheses may be *categorized* under [ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/) and [T1071.001](https://attack.mitre.org/techniques/T1071/001/); **no tunneling, C2, exfiltration, or malicious intent was established**.

## Analyst decision

**Provisional disposition:** `SYNTHETIC_REVIEW_ONLY`. Neither finding warrants host isolation, account action, attribution or an incident declaration. Confidence is **high that the implemented predicates matched the fabricated fixture** and **not assessed for maliciousness or real-world detection accuracy**.

**If equivalent signals arose on authorized operational telemetry:** Verify DNS query/response provenance and client identity, compare historical NXDOMAIN baselines, associate lookups with endpoint processes, inspect domain registration or approved application behavior as permitted, and correlate proxy/EDR/file-transfer records before choosing escalation. A POST is not equivalent to an upload of sensitive data.

**Known gaps:** No genuine resolver/proxy/endpoint logs, no authenticated user/device context, no packet capture of external systems, no TLS analysis, no full TCP reassembly, and no malware or payload provenance.

## Independent reproduction and negative controls

From the repository root:

```bash
python projects/03-network-pcap/generate_fixture.py --output projects/03-network-pcap/synthetic_traffic.pcap
python projects/03-network-pcap/analyze_pcap.py projects/03-network-pcap/synthetic_traffic.pcap
python -m unittest discover -s projects/03-network-pcap -p 'test_*.py' -v
```

- Deterministic file: **1,907 bytes**, **20 packets**, SHA-256 `5fc309499252677ba5cd31106b611edde5fd1b941aed3cc2f87f216da4dd707c`.
- Expected output: **12 decoded events**; exactly the two findings and UTC timestamps listed in [`expected_findings.json`](expected_findings.json).
- **18 focused tests** cover negative controls, matched DNS transactions, replayed DNS replies, separate client identities, invalid packets and capture bounds.
- [PCAP overview](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/pcap-evidence-overview.svg), [DNS illustration](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/dns-nxdomain-investigation.svg), and [HTTP illustration](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/network/http-request-comparison.svg) are **offline vector interpretations**, not genuine Wireshark screenshots.

**Verification boundary:** An offline Python parser is not Wireshark or a production IDS. A real Wireshark inspection, application screenshot, full packet protocol validation, and live telemetry analysis remain pending.
