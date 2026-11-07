# Active Directory attack-chain investigation

[Open the interactive case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/ad-attack-chain.html).

Independent analysis of OTRF's recorded PurpleSharp emulation: 25,993 host events and 1,121 packets, seven distinct-account failures, five RC4 service requests and three remote PowerShell process trees. Native execution clocks, host/logon/GUID joins and packet tuples distinguish supported associations from causal claims.

- [Full analyst report](08-ad-investigation/CASE_REPORT.md)
- [Executed analyzer](08-ad-investigation/analyze.py) and [tests](08-ad-investigation/test_analysis.py)
- [Evidence JSON](08-ad-investigation/analysis.json) and [CSV index](08-ad-investigation/evidence.csv)
- [Unexecuted SPL candidate](08-ad-investigation/normalized_candidates.spl) and [Sigma seed](08-ad-investigation/remote_powershell_sigma.yml)

Public recorded emulation, not an original owner-run capture or production incident. Legitimate administration can create the observed remote process pattern.
