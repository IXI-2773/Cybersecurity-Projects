# LAB-ID-001 — enterprise account investigation

This offline exercise correlates six normalized Windows-style identity events: three failed logons, a successful logon, a privileged group change, and a separate benign service sign-in.

## Reproduce

```bash
python projects/06-enterprise-account/analyze_account.py \
  projects/06-enterprise-account/account_events.csv \
  --output /tmp/account-analysis.json \
  --summary /tmp/account-summary.json
python projects/06-enterprise-account/test_account_analysis.py
```

The fixture uses reserved documentation IP addresses and does not represent a real user, domain controller, or organization.
