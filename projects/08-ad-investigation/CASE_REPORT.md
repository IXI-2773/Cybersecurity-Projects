# Active Directory: from authentication burst to remote execution

Independent analysis by Don Lopez, 2026-10-24. Source: OTRF Security-Datasets, PurpleSharp Active Directory Playbook I, recorded 2020-10-22. This is analysis of public recorded emulation telemetry, not a production incident or a claim that I operated the original environment.

## Assessment

The capture supports seven distinct-account failures, five successful RC4 service-ticket requests, IPC$/srvsvc access checks on three hosts, and three GUID-linked wsmprovhost.exe → powershell.exe executions. A shared domain account, source process, transport tuples and bounded timing connect the observations. These are six rule/context findings, not six confirmed compromises.

The producer labels the scenario password spraying (T1110.003), Kerberoasting (T1558.003), share discovery (T1135) and WinRM lateral movement (T1021.006). I used those notes as hypotheses. The records do not independently prove shared-password use, offline cracking, file theft, persistence, or malicious intent.

## Source integrity and coverage

The [source manifest](../../docs/research/2026-10-24-ad-investigation-source-intake.json) pins OTRF commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` and both download URLs. ZIP and member SHA-256 values appear in [analysis.json](analysis.json). Downloads are bounded, verified before parsing, and never extracted or executed. MIT source attribution and permission are retained in [SOURCE_LICENSE.txt](SOURCE_LICENSE.txt).

| Input | Complete coverage | Analyzed subset |
| --- | ---: | --- |
| Host NDJSON | 25,993 records, four hosts, seven providers | 226 records: Sysmon 1/3 and Security 4624/4625/4769/5145 |
| Ethernet PCAP | 1,121 packet records | 1,048 transport headers decoded; 61 truncated IPv4 and 12 unsupported transport records excluded |

PowerShell script blocks and other unselected events remain in the original source; this report does not claim exhaustive payload analysis. The browser includes all 226 selected host field excerpts and only the packets referenced by remote findings. Packet count is not a count of sessions or unique HTTP operations: retransmissions are not reassembled or deduplicated.

## Time policy

`@timestamp` is treated as collection time, not execution time. Sysmon `UtcTime` supplies native UTC. Security `EventTime` lacks an offset; I infer a capture-local UTC−04:00 conversion because all 24 Sysmon process-start pairs agree with it to the source's sub-second precision (0 ≤ difference < 1 second). This is a calibrated capture assumption, not a claim about geographic timezone or universal host clock accuracy.

Security events retain second precision. PCAP uses its recorded epoch. Cross-source windows allow bounded imprecision; native process ordering remains more precise. The DC child H24051 executed at 08:29:58.095 UTC but was collected at 08:30:37.907 UTC, a 39.812-second delay. Sorting solely by collection time would make the DC execution appear much later. Select both clocks in the interactive timeline.

## Evidence-backed chronology

H references are one-based physical lines in the pinned NDJSON; each excerpt carries provider, EventID, RecordNumber and the SHA-256 of the original line including its newline. P references are one-based PCAP packet records with byte offset and captured-frame SHA-256. Excerpts are field whitelists, not full original records.

| UTC event time | Observation | Source references | Evidential strength |
| --- | --- | --- | --- |
| 08:29:52.016 | PurpleSharp.exe starts on WORKSTATION5 as THESHIRE\\pgustavo, PID 7520, logon 0x9cc0b6 | H00019 | Direct process record |
| 08:29:53 | Seven 4625 failures, distinct target accounts, same caller host/PID/account/session | H00788, H00790, H00792, H00794, H00796, H00798, H00803 | Host/PID/session association to H00019; no ProcessGuid in 4625 and no source IP |
| 08:29:53–54 | Five successful 4769 requests, RC4 0x17, non-machine services, pgustavo@THESHIRE.LOCAL, client ::ffff:172.18.39.5 | H01125, H01136, H01140, H01144, H01148 | Direct ticket fields; not cracking evidence |
| 08:29:54 | 5145 IPC$/srvsvc checks on DC, WORKSTATION7 and WORKSTATION6 | H01198, H01284, H01324 | Same account/client across hosts; full RPC operation not decoded |
| 08:29:57.967 | WORKSTATION6 wsmprovhost parent → PowerShell child; same target logon 0x8fc6d5 | H03601 → H04447; 4624 H02459 | Same host + parent ProcessGuid + account/session |
| 08:29:58.036 | WORKSTATION7 equivalent parent/child, logon 0x9b1ad0 | H03833 → H04352; 4624 H01310 | Same direct joins |
| 08:29:58.095 | DC equivalent parent/child, logon 0x2125fe4 | H23781 → H24051; 4624 H02542 | Same direct joins; delayed collection |

Network corroboration ties outgoing Sysmon 3 records from the H00019 ProcessGuid to the targets on TCP/5985. For example H03882 is client 172.18.39.5:58218 → 172.18.39.6:5985; packet P00872 contains a single-packet `POST /wsman?PSVersion=5.1.18362.1110 HTTP/1.1` request on that tuple. H02795/P00839 corroborate WORKSTATION7; H02800/P00843 corroborate the DC. The report retains additional matching packets and flows.

Target IPs are inferred from the local endpoint of Sysmon connection events: SourceIp for initiated events, DestinationIp for received events. SourceIp on a received event is not the server's address. Ambiguous target-IP observations prevent corroboration. Exact tuple plus time connects a packet to a client flow, while account/target/time associates that flow with target execution. There is no end-to-end request ID tying a packet to a PowerShell child. The target 4624 records themselves have missing IpAddress; the page does not invent one.

## Detection design

| Candidate | Executed Python condition | Interpretation and gap |
| --- | --- | --- |
| ACCOUNT_SPRAY | ≥5 distinct targets in an inclusive 15-second sliding window; same host, caller account, PID and session; Security 4625 | Seven match. Local LogonType 2 is preserved. Does not establish a remote source, common password or successful access. |
| RC4_SERVICE_BURST | ≥5 distinct services in 15 seconds; Security 4769 status 0x0, encryption 0x17, same DC/principal/client; exclude machine `$` names and krbtgt | Five match. Twelve other 4769 records are retained as controls. Legacy RC4 activity can match; low-and-slow or AES roasting can evade. |
| IPC_SHARE_CONTEXT | IPC$ + srvsvc checks on ≥2 hosts in 15 seconds, same account/client | Three hosts. Context for discovery, not a standalone high-severity alert. |
| REMOTE_POWERSHELL | Sysmon 1 child powershell.exe with wsmprovhost.exe parent, exact same-host parent GUID, matching account/session and 0–10-second parent age | Three children. Matching Security 4624 type 3 session within −2…15 seconds and tuple/time-associated client WSMan packets strengthen context. Legitimate WinRM produces the same tree. |

Provider+EventID identities, explicit THESHIRE↔theshire.local aliasing, mapped IPv4 normalization and numeric PID/logon normalization prevent accidental mismatches. Deduplication uses host/provider/channel/record number plus raw hash; conflicting duplicates fail. Different domains, hosts or sessions do not merge. The implementation selects one strongest window per group and is bounded to this capture, not a complete streaming detector.

[normalized_candidates.spl](normalized_candidates.spl) and [remote_powershell_sigma.yml](remote_powershell_sigma.yml) are **unexecuted candidate translations**. The Python reference and its tests executed; Splunk and a Sigma backend did not. The Sigma rule is only a broad process-tree seed, not the multi-event correlation. Backend field extraction, clock handling, inclusive boundaries, late arrivals, duplicates, service baselines and tuning require separate deployment validation.

## Alternative explanations and next evidence

| Hypothesis | Compatible observations | Discriminating next evidence |
| --- | --- | --- |
| Authorized emulation or remote administration | Known PurpleSharp process, WinRM hosting, same operator on three targets | Change approval, operator activity, command/script blocks, complete original capture context |
| Legacy service/client behavior | RC4 tickets can be legitimate | SPN ownership, service encryption configuration, ordinary request frequency and source population |
| Attack-like credential activity and lateral movement | Distinct-account burst, service-ticket burst, multi-host IPC$ and remote process trees in seconds | Password outcomes, ticket extraction artifacts, full command content, target actions and authentication provenance |
| Collection delay mistaken for a second activity wave | DC records arrive ~40 seconds later | Native UtcTime, collector metadata, clock calibration; already resolved within this capture |

Twenty-three tests exercise domain/provider isolation, PID/session/host separation, threshold boundaries, duplicate references, archive tampering, packet truncation/fragmentation, required GUID joins and missing corroboration. Capture perturbations change source ports or remove 4624 records: process findings remain, but complete network corroboration is withheld. A manually frozen source-reference oracle checks the full-capture findings. These are correctness checks on one known emulation, not estimates of precision, recall or false-positive rate on a representative enterprise population.

## Reproduce

Python standard library only; approximately 2 MB of pinned ZIP downloads, 40 MB uncompressed host data. Analysis never runs emulation binaries.

```sh
python -m unittest discover -s projects/08-ad-investigation -p 'test_*.py'
python projects/08-ad-investigation/analyze.py --source-dir /tmp/portfolio-ad-source --download --check
```

Omit `--check` to regenerate analysis.json, evidence.csv and assets/js/ad-evidence.js. Existing archives must pass the same hashes. The generated evidence CSV is a navigation index, not the complete source dataset.

Primary references: [OTRF scenario](https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201022042947.html), [Sysmon ProcessGuid](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Windows 4625 fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625), [Windows 4769 fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769). The captured 2020 event schema predates later 4769 field additions.
