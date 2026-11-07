# Cybersecurity Projects — Don Lopez

[Portfolio](https://ixi-2773.github.io/Cybersecurity_Portfolio/) · [All projects](#all-projects) · [Run a project](#run-a-project)

Public security investigations, runnable labs, analyst tools and supporting research summaries. Each entry below links directly to its implementation or evidence and the portfolio write-up.

## Start here

| Project | Result and scope | Open |
| --- | --- | --- |
| **Active Directory investigation** | Independently correlated 25,993 host events and 1,121 packets from OTRF's recorded emulation; six qualified findings. | [Code and report](projects/08-ad-investigation/) · [Incident PDF](projects/08-ad-investigation/AD_Incident_Report.pdf) · [Visual case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/ad-attack-chain.html) |
| **Splunk authentication detection** | Corrected the inclusive 600-second boundary; the saved synthetic-lab result improved from 3/5 to 5/5 expected findings. | [Query and evidence](projects/01-authentication-detection/) · [Saved result](assets/evidence/splunk-native-dashboard-results.png) · [Visual case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/detection-engineering.html) |
| **Python SOC Triage Assistant** | Executed CSV/JSON walkthrough: 13 accepted events, three review candidates and six quarantined rows; partial processing stays visible. | [Tool and usage](projects/10-soc-triage/) · [Recorded JSON](projects/10-soc-triage/artifacts/case.json) · [Visual case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/soc-triage-automation.html) |

## All projects

### Investigations and runnable labs

| Project | Tools and evidence | Portfolio |
| --- | --- | --- |
| [Linux access audit with SQL](projects/09-linux-access-audit/) | Linux, SQLite, Python; two permission corrections with actual access retests. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/linux-sql-access-audit.html) |
| [Active Directory investigation](projects/08-ad-investigation/) | Python, Sysmon, Kerberos, PCAP; recorded third-party emulation analysis. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/ad-attack-chain.html) |
| [Splunk authentication detection](projects/01-authentication-detection/) | SPL and Python; synthetic fixtures, boundary correction and saved dashboard. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/detection-engineering.html) |
| [Windows process triage](projects/02-windows-process-triage/) | Python, Event 4688; two review candidates and benign controls in synthetic data. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/windows-process-triage.html) |
| [Network packet analysis](projects/03-network-pcap/) | Python and PCAP; generated 20-frame DNS/HTTP fixture and source-linked findings. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/network-traffic-analysis.html) |
| [Web attack-log analysis and hardening](projects/04-local-vulnerability-assessment/) | Python and HTTP; loopback requests, retained logs and remediation retest. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/vulnerability-remediation.html) |
| [Phishing email investigation](projects/05-phishing-email/) | RFC 5322, Python; lab-created message, header checks and safe indicator extraction. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/phishing-investigation.html) |
| [Enterprise account investigation](projects/06-enterprise-account/) | Python and CSV; fabricated sign-in and privilege-change timeline with alternative explanations. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/identity-mfa-investigation.html) |
| [Forensic evidence examination](projects/07-forensic-evidence/) | Python and hashes; generated evidence package, working-copy examination and artifact citations. E3 classroom experience is separately described. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/e3-digital-forensics.html) |

### Tools and software

| Project | Implementation and status | Portfolio |
| --- | --- | --- |
| [SOC Triage Assistant](projects/10-soc-triage/) | Runnable Python CLI, synthetic inputs, actual HTML/JSON output and focused tests. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/soc-triage-automation.html) |
| [Splunk execution workflow](splunk_workflow/) | Runbooks, verifier and [app source](splunk_app/don_lopez_soc/); offline validation exists, live indexing and fired-alert validation remain pending. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/splunk-execution-workflow.html) |
| [Certification learning engines](projects/certification-learning-engine.md) | Public [Security+ source](https://github.com/IXI-2773/Comptia-SY0-701-Test-Learning-Engine) and [SC-900 source](https://github.com/IXI-2773/Microsoft_SC-900_Test_Learning_Engine) remain in their existing repositories. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/certification-learning-engine.html) |

### Training and playbooks

| Project | Available material and scope | Portfolio |
| --- | --- | --- |
| [Network intrusion investigation](projects/network-intrusion-lab.md) | Résumé lab account covering Kali, Wireshark and Snort; original session evidence is not included. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/network-intrusion-lab.html) |
| [Offensive security VM training](projects/offensive-security-vm-labs.md) | Owner-confirmed Kali, VMware, Necromancer and HackThisSite practice; defensive takeaways and evidence limits. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/offensive-security-vm-labs.html) |
| [Kali VM and network visibility](projects/kali-defender-visibility.md) | Prior lab experience connected to separately identified public packet-analysis artifacts. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/kali-defender-visibility.html) |
| [Splunk threat investigation playbook](projects/splunk-threat-hunting.md) | Illustrative SPL searches and analyst questions for authentication, execution and persistence. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/splunk-threat-hunting.html) |

### Research systems

| Project | Public material | Portfolio |
| --- | --- | --- |
| [Celestial Resonance](projects/celestial-resonance.md) | Architecture summary of private research engineering; private implementation is excluded. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/celestial-resonance.html) |
| [Research AI Infrastructure](projects/research-ai-infrastructure.md) | Architecture summary of private evidence-aware research software; private implementation is excluded. | [Case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/research-ai-infrastructure.html) |

## Run a project

Python labs use the standard library unless their individual instructions state otherwise. Start with the offline SOC Triage Assistant:

```sh
python projects/10-soc-triage/triage.py projects/10-soc-triage/fixtures/authentication.csv projects/10-soc-triage/fixtures/processes.json --output-dir soc-triage-case
```

Use a new output directory. Open the generated `report.html` locally. The supplied walkthrough deliberately returns exit code **2 / PARTIAL**, retaining rejected rows. Its [README](projects/10-soc-triage/README.md) explains the input contract and result.

For another project, open its folder and follow its README. Linux permission checks require the environment described in their instructions; Splunk runtime steps require your own authorized instance. Run the focused tests for the project you change.

## Working here

Project code, fixtures and evidence are maintained here. The [portfolio](https://ixi-2773.github.io/Cybersecurity_Portfolio/) provides the visual case studies and links back to this collection. Study applications retain their existing source repositories; CR and RAI remain private.

The initial import preserves executable and evidence bytes from the portfolio's published source. [Import provenance](docs/IMPORT.md) and the [file manifest](docs/IMPORT_MANIFEST.json) identify that snapshot. Existing results retain their original dates and limits; importing them is not a new experiment.
