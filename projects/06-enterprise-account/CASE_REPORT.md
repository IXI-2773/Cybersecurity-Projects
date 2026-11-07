# LAB-ID-001 — enterprise account investigation report

## Question

Does the sequence of failures, successful sign-in, and privileged group change justify escalation as a linked identity event chain?

## Observations

- Three Event 4625 failures occurred for `dlopez` from `198.51.100.24` between 16:00Z and 16:04Z.
- Event 4624 recorded a successful sign-in from the same source at 16:07Z.
- Event 4728 recorded a privileged group change for the same account at 16:09Z.
- A separate service sign-in provides a benign control and is not included in the linked chain.

## Assessment

The five linked events justify escalation for account validation and containment. They do not prove account compromise by themselves. An authorized administrator, help-desk reset, or approved automation could explain part of the sequence; identity-provider context, endpoint telemetry, change records, and account-owner confirmation are still required.

## Recommended response

Validate the privileged change, preserve identity and host telemetry, review active sessions and recent account changes, and disable or contain the account if authorization cannot be established.

## Scope

All six rows are lab-created normalized events using reserved addresses. No domain controller, identity provider, endpoint, user, or production tenant was queried.
