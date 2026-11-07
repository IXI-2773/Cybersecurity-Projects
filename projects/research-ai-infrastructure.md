# Research AI Infrastructure — Evidence-Aware Engineering

**Don Lopez · Private research software · Public-safe summary**

Research AI Infrastructure (RAI) addresses a common failure mode in analysis: confident-sounding output despite missing, conflicting or misattributed evidence. Its high-level design separates evidence-backed findings from unsupported conclusions and keeps research output distinct from permission to take action.

The architecture includes research memory and retrieval, document ingestion,
source attribution, deterministic calculation tools and replaceable model/provider
components. RAI remains an independent project; a future CR boundary must preserve
the separate authority of each system. Historical implementation and verification
are distinct from activation of a live research service.

## Interactive public explanation

The [website case](https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/research-ai-infrastructure.html#rai-demo-title) traces a
structured claim to two fictional source records. Removing a required source
produces a coverage gap. Incorrect attribution produces a separate hold.
Conflicting observations stay visible; an agreement result requires both
correctly attributed records to support it.

This narrow public example checks structured coverage and attribution, not
arbitrary prose or source truth. It does not run private RAI code or a live model.

## Design principles

- **Evidence coverage:** identify the source basis for a claim and whether a conclusion is fully supported.
- **Preserving conflict:** retain disagreements rather than collapsing different observations into unearned certainty.
- **Provenance:** make attributions and transformations inspectable where feasible.
- **Bounded authority:** research may inform decisions but does not independently authorize external effects.
- **Replaceability:** avoid irreversible coupling to one model, library or service.

## A public example of the principle

The independent generated packet lab records DNS failures and an HTTP POST.
The decoded observations justify review but do not independently establish
command-and-control or exfiltration. A useful case separates what was decoded,
what an analyst suspects, and what corroborating evidence is still missing.

That distinction illustrates RAI's evidence-handling design focus. It is a
teaching example from the public lab, not output from the private RAI runtime.

- [Packet case report](03-network-pcap/CASE_REPORT.md)
- [Deterministic expected findings](03-network-pcap/expected_findings.json)

## Relation to defensive security

SOC analysts face similar problems: alerts can be incomplete, telemetry can disagree, and case notes can overstate what happened. These practices motivate a cautious [analyst triage playbook](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/SOC_TRIAGE_PLAYBOOK.md) and the public [evidence matrix](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/DETECTION_EVIDENCE_MATRIX.md).

## Scope and verification

Private implementation details are intentionally excluded. This summary **does not** establish autonomous SOC performance, production reliability, deployed security controls or real-world security accuracy. Public exercises are independent, reproducible demonstrations with fabricated data.

[All case studies](CASE_STUDIES.md) · [Recruiter overview](https://github.com/IXI-2773/Cybersecurity_Portfolio/blob/4eff2aa84ddec581d1127eb12d5a3ac9dc2fff89/docs/RECRUITER_OVERVIEW.md)

**Designed website page (when GitHub Pages is enabled):** https://ixi-2773.github.io/Cybersecurity_Portfolio/projects/research-ai-infrastructure.html
