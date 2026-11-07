# LAB-MAIL-001 — phishing email investigation

This offline exercise preserves and analyzes a harmless lab-created RFC 5322 message. All domains use reserved `.example` or `.invalid` namespaces. The analyzer performs no DNS lookups, HTTP requests, attachment execution, or mailbox access.

## Reproduce

```bash
python projects/05-phishing-email/analyze_email.py \
  projects/05-phishing-email/sample_message.eml \
  --output /tmp/mail-analysis.json \
  --summary /tmp/mail-summary.json
python projects/05-phishing-email/test_email_analysis.py
```

The test binds the message SHA-256, parsed fields, safely defanged URL, findings, and canonical JSON result.

## Evidence boundary

The message is a purpose-built training fixture. The completed work is the preservation, parsing, comparison, interpretation, and reporting performed against that fixture—not a claim about a real employee, mailbox, brand, or incident.
