# Advanced Active Directory investigation: verified source intake

The portfolio owner requested more advanced experience work. The current portfolio has several small, independent authentication, process, packet, phishing, account, and forensic cases. This intake identifies a larger coherent public capture that can support a deeper investigation.

## Selected candidate and observed coverage

OTRF PurpleSharp Active Directory Playbook I (2020-10-22):
https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201022042947.html

The producer describes password spraying, Kerberos service-ticket requests, network-share access tests, and WinRM lateral movement. Those are producer-described scenario activities, not findings independently established by this intake.

Downloaded, hashed, and inspected the host and network archives. Re-downloaded both from source commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` and confirmed exact SHA-256 agreement. The companion JSON records pinned URLs, archive hashes, member names/sizes, and counts.

- 25,993 parsed host events across four named lab hosts.
- 22,054 Sysmon events and 2,843 Security-Auditing events, with PowerShell and WMI activity also present.
- 1,121 classic-PCAP packet records. Capture packet timestamps span 08:29:53–08:30:08 UTC; host `@timestamp` values span 08:29:48.785–08:30:42.832 UTC on 2020-10-22.
- Windows logs and packets overlap in time, but entity resolution and causal relationships have not yet been established.

## Proposed technical investigation

Reconstruct one chain from source-attributed events: password spraying → service-ticket requests → share discovery → remote execution over WinRM. Preserve event provider plus EventID (IDs alone are not globally unique), host identity, account identity, process IDs/GUIDs where present, UTC times, and raw-record/packet references.

Validate which telemetry is actually present before choosing correlation rules. Map source/destination hosts, account domains, session identifiers, process relationships, and network flows; document any fields or phases absent from this capture. Use the producer's scenario notes as a separate ground-truth reference, not as invented event evidence.

Deliverables proposed for the next implementation slice: normalized evidence table, process/entity timeline, explainable correlation logic, SPL/Sigma where source fields support them, negative controls and counterexamples, findings with raw references, false-positive/blind-spot discussion, a final analyst report, and an interactive case page. Genuine tool captures should be taken only from tools actually run on this dataset.

## Boundaries and current status

This is public lab-capture research and the owner's new independent analysis. Do not represent it as a production incident, employer engagement, personal operation of OTRF's lab, or previously completed training. No adversary commands or binaries were executed. No payload was extracted or run. This intake parsed JSON metadata and PCAP record framing only; it did not validate application protocols, detection performance, compromise, persistence, or exfiltration.

No new completed investigation or honors entries have been published. LinkedIn honors synchronization awaits readable source content: the supplied detail URL was behind a sign-in wall, and the selected Google flow offered account creation rather than access to the existing profile. No account-creation confirmation was submitted. Preserve existing transcript-backed Dean’s List entries while waiting for the actual honors content.
