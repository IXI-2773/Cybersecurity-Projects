# Case study: RDP source restriction and partial firewall-rule overlap

- **Original lab implementation and analysis:** Don Lopez
- **Environment:** fabricated IPv4 `iptables-save` filter/INPUT rules, reviewed offline
- **Evidence status:** reproduced with the repository CLI; **no live firewall, host or external network was examined**

## The result at a glance

A later RDP allow rule was preceded by two `DROP` ranges. Those earlier rules covered **three quarters of the IPv4 source address space**, but the later rule still allowed TCP/3389 from the remaining quarter *within this simplified INPUT model*. The reviewer flagged both a broad administrative-source rule and a partial overlap.

I then modeled a proposed source restriction to a **fabricated, documentation-only management subnet** (`192.0.2.0/24`). Rerunning the same reviewer reduced the two modeled findings to zero. This is an **offline demonstration**, not a deployed remediation or a real-world security claim.

| Evidence | Baseline | Proposed follow-up |
| --- | --- | --- |
| Last INPUT rule (line 8) | TCP/3389 `ACCEPT` from any IPv4 source | TCP/3389 `ACCEPT` from `192.0.2.0/24` |
| Earlier rules | `DROP` for `0.0.0.0/1` and `128.0.0.0/2` | Identical earlier rules |
| Findings | `UNRESTRICTED_ADMIN_SOURCE` (HIGH); `PARTIALLY_SHADOWED_RULE` (INFO) | No modeled findings |
| CLI exit | `1` — findings present | `0` — no modeled findings |
| Retained input | [Baseline export](fixtures/iptables_partial_overlap.rules) | [Restricted-source export](fixtures/iptables_partial_overlap_restricted.rules) |
| Retained output | [JSON](artifacts/partial_overlap_report.json) · [HTML](artifacts/partial_overlap_report.html) · [CSV](artifacts/partial_overlap_report.csv) | [Follow-up JSON](artifacts/partial_overlap_restricted_report.json) |

## How I investigated

1. **Read the rule order.** `INPUT:L6` drops `0.0.0.0/1`; `INPUT:L7` drops `128.0.0.0/2`. Both are terminating matches, so packets they match do not reach later INPUT rules in this model.
2. **Identify the uncovered portion.** The two ranges together cover 75% of IPv4 source addresses. `192.0.0.0/2` is not covered by those two source ranges, so the later RDP allow can still match traffic from that portion *if other, unmodeled conditions permit it*.
3. **Separate the findings.** `UNRESTRICTED_ADMIN_SOURCE` flags the written allow rule's unrestricted source; `PARTIALLY_SHADOWED_RULE` explains redundant matches with earlier DROP rules. Partial overlap must **not** suppress the source-exposure review candidate.
4. **Ask what the rule was intended to allow.** Before recommending a real change, an analyst would verify the approved administration subnet, actual services and systems, change owner, default policy, and dependencies. None of those facts are established by this fabricated export.
5. **Model a proposed correction.** Keep the original two DROP rules and default-deny policy; restrict the later TCP/3389 allow to `192.0.2.0/24`. This address range is a stand-in for a separately verified, approved administration source—not a production subnet.
6. **Re-run and compare.** The CLI reports three rules and zero findings for the proposed follow-up. That means the defined static checks no longer flag this example; it does **not** establish that live RDP access is safe or functional.

## Reproduce the evidence

From the repository root, run the tool against the two included synthetic inputs:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_partial_overlap.rules
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_partial_overlap_restricted.rules
```

The first command exits `1` with two findings; the second exits `0` with an empty `findings` list. The linked JSON artifacts retain the exact responses. No firewall rules are applied, and the commands make no network requests.

## What I would validate before a production change

- Obtain authorization, a change ticket and an owner-approved source range. A subnet chosen for illustration is not an acceptable production allowlist.
- Confirm relevant `INPUT` paths, network interfaces, IPv6, NAT, routing, connection state, other chains and upstream security controls—outside this tool's supported subset.
- Assess the effect on legitimate administration and emergency access; plan a rollback before changing any real rules.
- Use an approved maintenance window and independent access tests to verify the intended connections work and unintended ones are refused. Retain the before/after configuration and test evidence.

**Interview takeaway:** I built an offline Python reviewer that distinguishes complete shadowing from partial overlap, preserves potentially important exposure warnings, and exports source-linked evidence. I demonstrated an analyst workflow using fabricated rules and a reproducible before/after comparison; I do not represent it as production incident-response experience.

Implementation, supported syntax, safe-use boundaries and conceptual upstream attribution are documented in the [project README](README.md).
