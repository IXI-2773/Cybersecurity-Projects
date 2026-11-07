# LAB-MAIL-001 — phishing email investigation report

## Question

Does the preserved message contain enough observable inconsistency to justify quarantine and escalation without visiting its link?

## Preserved evidence

- Source: `sample_message.eml`, a harmless lab-created RFC 5322 message.
- SHA-256: `d110efbb542d29e4a0b5e29a2479a637c435d26c98dd872ff85fc6c5e0ba5442`.
- Message-ID: `<lab-mail-001@contoso.example>`.
- All domains are reserved examples. No network request was made.

## Findings

1. `MAIL_REPLY_TO_MISMATCH` — the visible sender uses `contoso.example`; replies route to `contoso-login.example`.
2. `MAIL_AUTH_FAILURES` — the supplied Authentication-Results record reports SPF fail, DKIM none, and DMARC fail.
3. `MAIL_LINK_DOMAIN_MISMATCH` — the single extracted URL uses the Reply-To domain rather than the sender domain. It is displayed only as `hxxps://contoso-login[.]example/verify?account=analyst`.

## Assessment and response

The combined inconsistencies support treating the lab message as suspicious. Quarantine it, prevent user interaction, search for matching Message-ID/sender/link indicators, verify the request through a trusted channel, and review mailbox, proxy, DNS, and endpoint telemetry before claiming impact.

## Limits

This exercise does not prove delivery to a real mailbox, user interaction, credential submission, malware execution, or malicious control of any infrastructure. The conclusion applies only to the preserved fixture.
