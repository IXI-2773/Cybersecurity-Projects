# Firewall Policy Reviewer — starter tool

![Portfolio project](../../assets/badges/portfolio-project.svg)

**Original implementation:** Don Lopez · **Category:** defensive network configuration review · **Input:** fabricated JSON and limited `iptables-save` exports · **Reports:** JSON, HTML and CSV · **Runtime:** Python 3.10+ standard library · **Network:** none.

This small CLI makes firewall-rule *review candidates* easy to explain to an interviewer. It reads a local, deliberately simplified policy file and reports:

**Start here for a hiring-manager review:** [RDP source restriction and partial-overlap case study](CASE_STUDY.md). It connects a fabricated input, original findings, an analyst's reasoning and a reproduced follow-up result. For a visual artifact, see the [HTML findings report](artifacts/partial_overlap_report.html).

| Finding code | Trigger | Interpretation |
| --- | --- | --- |
| `UNRESTRICTED_ADMIN_SOURCE` | Allow TCP/22, 3389, 5985 or 5986 from IPv4/IPv6 `/0` | Administrative service source range needs review |
| `ANY_TO_ANY_ALLOW` | Allow protocol `any` from `/0` to `/0` | Unrestricted traffic rule needs review |
| `DEFAULT_ALLOW` | Policy's fallback action is `allow` | Verify least-privilege design |
| `SHADOWED_RULE` (iptables mode) | An earlier terminating rule fully covers one later rule's source, destination, protocol and port | Later rule is unreachable within the supported INPUT model; maintenance review, not an exposure |
| `COMBINED_SHADOWED_RULE` (iptables mode) | Two or more earlier terminating rules jointly cover every source/destination address and protocol/port of a later rule | Later rule is unreachable within the supported INPUT model; report lists contributing earlier rule IDs |
| `PARTIALLY_SHADOWED_RULE` (iptables mode) | Earlier terminal rules intersect a later rule's match set without covering it all | Lists overlapping rule IDs and one exact CIDR/protocol/port intersection; the later rule can still match other traffic |

Findings are heuristics, **not confirmed vulnerabilities**, exposure measurements or claims about a live firewall. `HIGH` and `CRITICAL` are tutorial review priorities, not CVSS scores.

## Run the example

From the repository root:

```sh
python projects/13-firewall-policy-review/review.py projects/13-firewall-policy-review/fixtures/synthetic_policy.json
python -m unittest discover -s projects/13-firewall-policy-review -p 'test_*.py' -v
```

The example intentionally exits **1** because two potential policy problems are present. Its captured [JSON report](artifacts/example_report.json) contains exactly those two findings, with rule IDs and descriptions. Exit codes: `0` = no modeled findings; `1` = one or more review candidates; `2` = unreadable or invalid policy. `0` does **not** certify a firewall as secure.

## Import a limited `iptables-save` export and check shadowing (v6)

The same CLI can also read **IPv4 `iptables-save -t filter` output**, without applying or changing firewall rules. For example, run the supplied fabricated export:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_filter.rules
```

The [retained import report](artifacts/iptables_report.json) records three findings across the original `INPUT:L7` and `INPUT:L8` line numbers, including a partial overlap on the final catchall rule. In an authorized Linux environment, you can export your own filter table with `iptables-save -t filter` and save it locally for offline review. **Never commit real infrastructure exports, internal addresses or sensitive rules to this public repository.**

For a first-match example, run:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_shadow.rules
```

Its [saved shadow report](artifacts/shadow_report.json) identifies an RDP allow rule that cannot run because an earlier `DROP` rule matches every packet. The reviewer emits `SHADOWED_RULE` instead of a misleading unrestricted-RDP warning for that later rule. A single earlier `ACCEPT`, `DROP` or `REJECT` may fully shadow a later rule if its source/destination CIDRs and protocol/port match set cover the later rule's entire set.

To see shadowing across **multiple** preceding rules, run:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_combined_shadow.rules
```

In this synthetic example, two earlier `DROP` rules cover opposite halves of the IPv4 source space; neither alone covers the later RDP allow. The [retained combined-shadow report](artifacts/combined_shadow_report.json) records `COMBINED_SHADOWED_RULE` with both contributing `INPUT:L` line IDs. The algorithm subtracts prior matching IPv4 source/destination CIDR regions exactly, accepting different terminal actions and retaining protocol/port restrictions. It **does not** call a partly overlapping rule shadowed unless the earlier rules collectively cover every possible packet in the simplified model.

To compare with an **incomplete overlap**, run:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_partial_overlap.rules
```

The two earlier `DROP` CIDRs cover three quarters of the source address space, leaving the final quarter unmatched by those rules. The [retained partial-overlap report](artifacts/partial_overlap_report.json) records `PARTIALLY_SHADOWED_RULE`, both earlier rule IDs and a concrete overlapping CIDR/port example. It **retains the `HIGH` unrestricted-RDP-source review candidate** because the later allow is not fully shadowed. The example is a witness of some overlap, **not** a complete overlap listing or a measured share of real traffic. Fully shadowed earlier rules are excluded from the reported overlap IDs.

## Open or export an analyst-readable report

Employers can download and open the **[saved HTML report](artifacts/partial_overlap_report.html)** in a browser, or inspect the **[saved CSV report](artifacts/partial_overlap_report.csv)** in a spreadsheet. Both come from the same fabricated partial-overlap fixture and retain rule IDs, findings, earlier-rule references, overlap evidence and scope limits. The HTML is self-contained—no JavaScript, external stylesheets or live data connections.

Create your own report from the repository root, using a filename that does not already exist:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save --report-format html --output firewall_review.html projects/13-firewall-policy-review/fixtures/iptables_partial_overlap.rules
python projects/13-firewall-policy-review/review.py --format iptables-save --report-format csv --output firewall_review.csv projects/13-firewall-policy-review/fixtures/iptables_partial_overlap.rules
```

Without `--output`, the chosen format is printed to standard output; without `--report-format`, the existing JSON output remains the default. Exit code `1` still means review candidates were found **even if the report file was saved successfully**. `--output` creates a new file and refuses to overwrite an existing file; invalid input does not create a report. CSV text is protected against leading spreadsheet formulas, and HTML text is escaped. No configuration is changed. **Do not publish a real firewall export or its report without authorization and redaction.**

The adapter intentionally supports a bounded subset:

- One complete `*filter` table with an `INPUT` default policy (`ACCEPT` or `DROP`) and `COMMIT`.
- IPv4 `-A INPUT` rules using `-s`, `-d`, `-p tcp`/`udp`/`all`, optional matching `-m tcp`/`udp`, one numeric `--dport`, and `-j ACCEPT`/`DROP`/`REJECT`. Unspecified addresses mean `0.0.0.0/0`.
- `INPUT` review only. Other built-in chains are outside this tool's analysis scope.

It rejects unsupported `INPUT` syntax, including conntrack/state matches, interface matches, negation, multiport/ranges, user-chain jumps, IPv6, and other tables. This is **not** a full iptables parser. Shadow detection handles complete coverage by **one or a combination of earlier terminal rules** and separately flags incomplete intersections, including when an earlier TCP/UDP port overlaps a later all-protocol rule. It does not estimate overlap percentages, simulate packets or recommend automatic rule removal. The exact-CIDR full-shadow analysis stops with exit code `2` and no partial report if its uncovered-region partition grows past 4,096 regions. Routing, NAT, other chains and real packet reachability are not evaluated; the output labels that limitation. Non-shadowed warnings remain review candidates, not proof that traffic can reach a destination.

Format references: [iptables-save manual](https://man7.org/linux/man-pages/man8/iptables-save.8.html) and [iptables rule syntax](https://man7.org/linux/man-pages/man8/iptables.8.html).

For the default JSON mode, input must be an object with `name` (text), `default_action` (`allow`/`deny`), and `rules` (array). Each rule has a unique `id`, `action` (`allow`/`deny`), IPv4/IPv6 CIDR `source` and `destination` of the same IP family, `protocol` (`tcp`, `udp`, or `any`) and `port` (1–65535 for TCP/UDP; `null` for `any`). Invalid or ambiguous input is rejected rather than silently analyzed. It reads local files only, makes no network calls and cannot change firewall rules.

## Scope and next extensions

- **Now:** three static checks on JSON plus a bounded IPv4 `iptables-save` filter/INPUT importer with single/combined shadowing, partial-overlap findings, reproducible JSON/HTML/CSV examples and a [before/after analyst case study](CASE_STUDY.md).
- **Next:** expand supported match syntax only when an authorized sample and focused tests establish a useful need.
- **Later:** pursue a properly authorized, sanitized real-world configuration case study and validate actual behavior with independent network evidence.

The reviewer does **not** fully parse iptables or parse nftables, Azure/AWS rules, NAT, interfaces, routing or zone precedence. Beyond exact match coverage in the supported INPUT model, it does not establish real reachability, account for upstream controls, infer asset criticality or replace a managed firewall audit.

## References and attribution

This is original Python code and illustrative data, **not a copied tool**. The first release takes conceptual inspiration from [CarterPerez-dev's firewall-rule-engine](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/firewall-rule-engine) (upstream AGPL-3.0) and [Anthropic-Cybersecurity-Skills' network segmentation workflow](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/implementing-network-segmentation-with-firewall-zones) (upstream Apache-2.0). Neither upstream source code nor skill text is vendored here; the references do not imply endorsement.
