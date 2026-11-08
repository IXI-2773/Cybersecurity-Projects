# Case study: reviewing unrestricted role assumption

- **Original lab and CLI analysis:** Don Lopez
- **Environment:** fabricated AWS IAM identity-policy JSON; no AWS connection, credentials, account, or real principal
- **Evidence:** retained input and output for two offline runs using the same reviewer

## The question

A synthetic identity policy allowed `sts:AssumeRole` against `Resource: "*"`, with a condition checking an example principal tag. Which roles might the statement permit, and what should an analyst verify before approving a narrower version?

The reviewer reports `ASSUMEROLE_ALL_RESOURCES` for this syntax. AWS documents that a wildcard role resource can permit assumption of roles **that also trust the principal**, subject to other applicable conditions and policy layers. This is a candidate for least-privilege review, **not proof of cross-account access or privilege escalation**.

| Evidence | Fabricated baseline | Fabricated proposed follow-up |
| --- | --- | --- |
| Policy | [Baseline JSON](fixtures/assumerole_broad_identity_policy.json) | [Restricted JSON](fixtures/assumerole_restricted_identity_policy.json) |
| `Action` | `sts:AssumeRole` | `sts:AssumeRole` |
| `Resource` | `*` | `arn:aws:iam::111122223333:role/example-response-readonly` |
| `Condition` | Example principal-tag condition, unevaluated | Same unevaluated condition |
| CLI finding | `ASSUMEROLE_ALL_RESOURCES` (REVIEW) | None of this reviewer's literal patterns |
| Retained report | [Baseline report](artifacts/assumerole_broad_report.json) | [Follow-up report](artifacts/assumerole_restricted_report.json) |
| CLI exit | `1` | `0` |

## My analysis workflow

1. **Identify the permission boundary.** In the supplied identity policy, `Resource: "*"` does not restrict the possible role ARN. A successful role assumption would still require the target role's trust policy, applicable conditions, and every other relevant policy layer to permit it.
2. **Record rather than infer conditions.** The reviewer records that a `Condition` exists, but deliberately does not interpret principal tags or other condition operators. Its finding cannot establish which requests succeed.
3. **Propose a scoped alternative.** In the follow-up *fictional* policy, I changed only the Resource field to one documentation-only role ARN and left the condition unchanged. The tool produced zero modeled findings. That is not an effective-permission test and does not establish that the policy works as intended.
4. **Define the real validation needed.** In an authorized environment, obtain the intended trust relationships and role ARNs, confirm approved workflows and account boundaries, review policy conditions, run IAM Access Analyzer and approved access tests, and plan rollback before a deployed change.

## Reproduce without AWS access

From the repository root:

```sh
python projects/14-iam-policy-review/review.py projects/14-iam-policy-review/fixtures/assumerole_broad_identity_policy.json
python projects/14-iam-policy-review/review.py projects/14-iam-policy-review/fixtures/assumerole_restricted_identity_policy.json
```

The baseline exits `1` with one review candidate; the follow-up exits `0` without a modeled candidate. Both retained JSON reports are checked against current CLI output in the project-focused tests.

## Scope and references

This offline demonstration reviews **identity-policy syntax only**. No source AWS resources or live findings exist; no remote policy change was performed. It does not simulate AWS permissions, evaluate explicit denies, trust policies, SCPs, permissions boundaries, session policies, resource policies, or conditions. It cannot validate the appropriateness of the example role.

- [AWS: grant a user permissions to switch roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-to-switch.html)
- [AWS: policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS: IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)

**Interview takeaway:** I built an original, read-only policy review script, identified a syntactic wildcard role-assumption candidate, modeled a narrower alternative, and retained reproducible input/output evidence. This demonstrates a defensive analysis process using invented data, not professional AWS incident-response experience.
