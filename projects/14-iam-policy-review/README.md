# AWS IAM Policy Reviewer — offline starter

![Portfolio project](../../assets/badges/portfolio-project.svg)

**Original implementation:** Don Lopez · **Category:** cloud identity / GRC review · **Input:** synthetic AWS IAM identity-policy JSON · **Runtime:** Python 3.10+ standard library · **Network and credentials:** none.

This small defensive CLI identifies **literal overbroad Allow patterns** in a deliberately limited identity-policy document. It produces a machine-readable report with statement references and review questions, **not** an AWS authorization decision, production finding, or security score.

**For an employer-facing walkthrough:** [Unrestricted role-assumption case study](CASE_STUDY.md). It links a simulated baseline, one proposed narrower policy, their exact machine-readable reports, and the validation steps that would be required before a real change.

## Walk through the retained synthetic evidence

| Evidence | Baseline fabricated policy | Proposed fabricated follow-up |
| --- | --- | --- |
| Input | [Broad identity policy](fixtures/broad_identity_policy.json) | [Restricted identity policy](fixtures/restricted_identity_policy.json) |
| Modeled findings | 2 review candidates | 0 review candidates |
| Findings | `ALL_ACTIONS_ALL_RESOURCES`; `PASSROLE_ALL_RESOURCES` | None of this tool's literal patterns |
| Retained JSON | [Baseline report](artifacts/broad_report.json) | [Follow-up report](artifacts/restricted_report.json) |
| CLI exit | 1 | 0 |

The baseline contains an `Allow` with `Action: "*"` and `Resource: "*"`, plus an `iam:PassRole` Allow with `Resource: "*"`. The latter has a `Condition`, which the tool **records but does not evaluate**. The follow-up replaces these two broad statements with illustrative, narrower resource scopes. All names, account numbers, roles and bucket names are fabricated examples. **No live account, policy, role or resource was accessed or changed.**

The [separate role-assumption example](CASE_STUDY.md) retains a `sts:AssumeRole` wildcard-resource baseline and one synthetic role-ARN follow-up. The baseline has one `ASSUMEROLE_ALL_RESOURCES` candidate; the proposed narrower example has no modeled candidates. **Neither output proves effective role access.**

Run from the repository root:

```sh
python projects/14-iam-policy-review/review.py projects/14-iam-policy-review/fixtures/broad_identity_policy.json
python projects/14-iam-policy-review/review.py projects/14-iam-policy-review/fixtures/restricted_identity_policy.json
python -m unittest discover -s projects/14-iam-policy-review -p 'test_*.py' -v
```

Exit `0` means no **modeled** review candidates, `1` means candidates were found, and `2` means input was unreadable or outside the supported grammar. The CLI reads local files and prints JSON; it has no AWS SDK dependency, cloud credentials, network requests or remediation actions.

## Supported scope

It accepts one IAM JSON document with `Version: "2012-10-17"`, a nonempty `Statement` object/list, and identity-based `Allow`/`Deny` statements with explicit `Action` and `Resource` strings/lists. Optional `Sid` provides a stable report reference; optional `Condition` is recorded as present but **not interpreted**. The narrow checks are:

- `ALL_ACTIONS_ALL_RESOURCES`: literal `Action: "*"` with `Resource: "*"`.
- `PASSROLE_ALL_RESOURCES`: literal `iam:PassRole` with `Resource: "*"`.
- `SERVICE_ACTIONS_ALL_RESOURCES`: literal service-wide pattern such as `s3:*` or `execute-api:*` with `Resource: "*"` (including hyphenated AWS service namespaces).
- `ASSUMEROLE_ALL_RESOURCES`: literal `sts:AssumeRole` with `Resource: "*"`; other policies and role trust still control actual access.

The reviewer treats AWS action names case-insensitively for exact `PassRole`/`AssumeRole` matches, and can emit multiple distinct review candidates for mixed action lists. Literal `Action: "*"` remains one umbrella candidate. Conditions are recorded as present but not interpreted.

Only `Allow` statements produce candidates. An unsupported element (including `NotAction`, `NotResource`, `Principal` or malformed field types) causes the full input to be rejected rather than reported clean. The tool does **not** calculate effective permissions, expand AWS action wildcards, analyze `Deny` overrides, evaluate `Condition`, resolve policy variables, or combine SCPs, permissions boundaries, session policies, resource-based policies, service-specific requirements or cross-account context. A missing candidate does not establish least privilege.

## Analyst follow-up

1. Confirm the policy type, attachment, relevant role or user, account and intended use.
2. Review the exact Allow statement and whether its wildcards are necessary; inspect any conditions manually.
3. Compare the proposed narrower action/resource scope against AWS's actual action-resource requirements and all other applicable policy layers.
4. Obtain authorization, simulate and test effective access in an approved account, and keep a rollback path before any real change.

The fixture models **the question to ask**, not the answer for a real cloud environment.

## References and provenance

- [AWS IAM JSON policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html) and [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html) explain why syntax-only checks cannot establish effective access.
- Conceptually informed by the cloud-security and identity-security areas in [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) and the educational project structure in [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects). **No source code was copied or vendored from either repository.**

**Next:** extend action/resource semantics only after a specific, authorized use case establishes what extra interpretation is needed. An employer-facing portfolio page can follow once this independent starter is reviewed.
