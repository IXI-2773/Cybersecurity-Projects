# Network Intrusion Investigation

Use packet evidence and IDS rules to investigate activity in an isolated lab.

Kali Linux · Wireshark · Snort · 2025

Résumé lab: 5,000+ packets analyzed, with Snort rule implementation and tuning.

## The investigation problem

A scan, repeated connection attempt or unusual application request needs context. Packet analysis makes the exchange inspectable; an IDS rule turns a chosen pattern into a repeatable signal. Neither removes the need for an analyst to explain the behavior.

## My lab work

I simulated scanning, brute-force and exploitation activity from Kali Linux in an isolated VMware lab, analyzed more than 5,000 packets in Wireshark, and implemented and tuned Snort rules for the simulated attacks.

The original capture and exact rule output are not stored in this repository. The separate generated DNS/HTTP exercise preserves the way I now present packet references and bounded findings publicly.

## From packet to finding

- **Bound the scenario.** Identify the lab systems, activity and capture interval.
- **Inspect the exchange.** Use protocol fields and conversation timing to explain the observed behavior.
- **Compare the alert.** Relate the Snort predicate and triggering traffic, and consider legitimate matches.
- **Document the conclusion.** Preserve packet references, rule context, limitations and the recommended next step.

## Network and VM walkthrough

The completed lab connected attacker-side VM activity, captured traffic and IDS review. [See the visual Kali VM and network-visibility walkthrough ↗](kali-defender-visibility.md).

## A public packet exercise

The generated 20-frame PCAP demonstrates DNS and HTTP analysis with a deterministic analyzer and expected findings. It is immediately inspectable, but it is not the original 5,000+ packet lab.

[Explore the generated packet case ↗](network-traffic-analysis.md)

## Scope and evidence

Completed lab work confirmed by me and described in my supplied résumé. Reference imagery and the linked smaller fixture are clearly separated from the unavailable original artifacts. This is lab experience, not a claim of a production incident or paid SOC employment.

Background reference

[MITRE ATT&CK: credential attack context ↗](https://attack.mitre.org/techniques/T1110/). This reference informs the investigation approach; it does not verify my lab results.

[Choose another case study ↗](https://ixi-2773.github.io/Cybersecurity_Portfolio/explore.html)

## Academic foundation

Completed coursework: IST 4210 Advanced Networking & Security and IST 4620 Penetration Testing & Ethical Hacking (Fall 2024).

[Explore the academic background](https://ixi-2773.github.io/Cybersecurity_Portfolio/education.html).
