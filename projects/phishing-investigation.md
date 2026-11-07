# Phishing Email Investigation

Completed offline analysis of a harmless lab-created RFC 5322 message.

![Reproducible phishing investigation result](https://raw.githubusercontent.com/IXI-2773/Cybersecurity_Portfolio/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/assets/evidence/phishing-investigation.svg)

The case preserves the message SHA-256, compares sender and Reply-To domains, reads the supplied SPF/DKIM/DMARC results, extracts and safely defangs one URL, and produces three review findings. No live link, mailbox, domain, attachment, or public target was contacted.

[Case report](05-phishing-email/CASE_REPORT.md) · [Fixture and analyzer](05-phishing-email/README.md) · [All case studies](CASE_STUDIES.md)

Academic foundation: IST 5250 Incident Handling & Cyber Investigation (Fall 2024). This is newly executed portfolio work, not a claim about a recovered class assignment.
