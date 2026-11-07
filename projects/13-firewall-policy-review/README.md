# Firewall Policy Reviewer — starter tool

![Portfolio project](../../assets/badges/portfolio-project.svg)

**Original implementation:** Don Lopez · **Category:** defensive network configuration review · **Input:** fabricated JSON policy · **Runtime:** Python 3.10+ standard library · **Network:** none.

This small CLI makes firewall-rule *review candidates* easy to explain to an interviewer. It reads a local, deliberately simplified policy file and reports:

| Finding code | Trigger | Interpretation |
| --- | --- | --- |
| `UNRESTRICTED_ADMIN_SOURCE` | Allow TCP/22, 3389, 5985 or 5986 from IPv4/IPv6 `/0` | Administrative service source range needs review |
| `ANY_TO_ANY_ALLOW` | Allow protocol `any` from `/0` to `/0` | Unrestricted traffic rule needs review |
| `DEFAULT_ALLOW` | Policy's fallback action is `allow` | Verify least-privilege design |

Findings are heuristics, **not confirmed vulnerabilities**, exposure measurements or claims about a live firewall. `HIGH` and `CRITICAL` are tutorial review priorities, not CVSS scores.

## Run the example

From the repository root:

```sh
python projects/13-firewall-policy-review/review.py projects/13-firewall-policy-review/fixtures/synthetic_policy.json
python -m unittest discover -s projects/13-firewall-policy-review -p 'test_*.py' -v
```

The example intentionally exits **1** because two potential policy problems are present. Its captured [JSON report](artifacts/example_report.json) contains exactly those two findings, with rule IDs and descriptions. Exit codes: `0` = no modeled findings; `1` = one or more review candidates; `2` = unreadable or invalid policy. `0` does **not** certify a firewall as secure.

## Import a limited `iptables-save` export (v2)

The same CLI can also read **IPv4 `iptables-save -t filter` output**, without applying or changing firewall rules. For example, run the supplied fabricated export:

```sh
python projects/13-firewall-policy-review/review.py --format iptables-save projects/13-firewall-policy-review/fixtures/iptables_filter.rules
```

The [retained import report](artifacts/iptables_report.json) identifies two review candidates by the original `INPUT:L7` and `INPUT:L8` line numbers. In an authorized Linux environment, you can export your own filter table with `iptables-save -t filter` and save it locally for offline review. **Never commit real infrastructure exports, internal addresses or sensitive rules to this public repository.**

The adapter intentionally supports a bounded subset:

- One complete `*filter` table with an `INPUT` default policy (`ACCEPT` or `DROP`) and `COMMIT`.
- IPv4 `-A INPUT` rules using `-s`, `-d`, `-p tcp`/`udp`/`all`, optional matching `-m tcp`/`udp`, one numeric `--dport`, and `-j ACCEPT`/`DROP`/`REJECT`. Unspecified addresses mean `0.0.0.0/0`.
- `INPUT` review only. Other built-in chains are outside this tool's analysis scope.

It rejects unsupported `INPUT` syntax, including conntrack/state matches, interface matches, negation, multiport/ranges, user-chain jumps, IPv6, and other tables. This is **not** a full iptables parser. Rule order, shadowing, routing, NAT, and effective packet reachability are not evaluated; the output labels that limitation. A finding is a review candidate even if another rule would prevent traffic.

Format references: [iptables-save manual](https://man7.org/linux/man-pages/man8/iptables-save.8.html) and [iptables rule syntax](https://man7.org/linux/man-pages/man8/iptables.8.html).

The input must be a JSON object with `name` (text), `default_action` (`allow`/`deny`), and `rules` (array). Each rule has a unique `id`, `action` (`allow`/`deny`), IPv4/IPv6 CIDR `source` and `destination` of the same IP family, `protocol` (`tcp`, `udp`, or `any`) and `port` (1–65535 for TCP/UDP; `null` for `any`). Invalid or ambiguous input is rejected rather than silently analyzed. It reads local files only, makes no network calls and cannot change firewall rules.

## Scope and next extensions

- **Now:** static illustration of three checks on JSON plus a bounded, fail-closed IPv4 `iptables-save` filter/INPUT importer, with fabricated fixtures and preserved line numbers.
- **Next:** model INPUT first-match semantics to distinguish reachable from shadowed rules; expand supported match syntax only with dedicated evidence and tests.
- **Later:** HTML/CSV analyst report with change tickets and evidence for remediation, plus a portfolio case study once independently executed on authorized data.

The reviewer does **not** parse iptables/nftables, Azure/AWS rules, NAT, interfaces, routing, rule order or zone precedence. It does not prove packet reachability, account for upstream controls, infer asset criticality or replace a managed firewall audit.

## References and attribution

This is original Python code and illustrative data, **not a copied tool**. The first release takes conceptual inspiration from [CarterPerez-dev's firewall-rule-engine](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/firewall-rule-engine) (upstream AGPL-3.0) and [Anthropic-Cybersecurity-Skills' network segmentation workflow](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/implementing-network-segmentation-with-firewall-zones) (upstream Apache-2.0). Neither upstream source code nor skill text is vendored here; the references do not imply endorsement.
