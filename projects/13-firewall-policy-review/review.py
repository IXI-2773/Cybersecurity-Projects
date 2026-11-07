#!/usr/bin/env python3
"""Read an illustrative JSON firewall policy and report review candidates.

This is an offline static review, not a parser for a vendor firewall or proof
of effective network access. No packets are sent and no rules are changed.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import sys

from iptables_import import parse_iptables_save
from report_export import render_csv, render_html
from rule_order import (combined_shadowed_by_prior_rules,
                        partially_shadowed_by_prior_rules, shadowed_by_prior_rule)


ADMIN_TCP_PORTS = {22, 3389, 5985, 5986}  # SSH, RDP, WinRM


def validate(policy):
    """Reject policy shapes we cannot interpret safely."""
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    if not isinstance(policy.get("name"), str) or not policy["name"].strip():
        raise ValueError("name must be nonempty text")
    if policy.get("default_action") not in {"allow", "deny"}:
        raise ValueError("default_action must be allow or deny")
    if not isinstance(policy.get("rules"), list):
        raise ValueError("rules must be an array")

    seen_ids = set()
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be an object")
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen_ids:
            raise ValueError("rule IDs must be nonempty and unique")
        seen_ids.add(identifier)
        if rule.get("action") not in {"allow", "deny"}:
            raise ValueError(f"{identifier}: action must be allow or deny")
        protocol = rule.get("protocol")
        if protocol not in {"tcp", "udp", "any"}:
            raise ValueError(f"{identifier}: unsupported protocol")
        port = rule.get("port")
        if protocol == "any" and port is not None:
            raise ValueError(f"{identifier}: protocol any requires port null")
        if protocol != "any" and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError(f"{identifier}: TCP/UDP requires a port between 1 and 65535")
        source = ipaddress.ip_network(rule["source"], strict=True)
        destination = ipaddress.ip_network(rule["destination"], strict=True)
        if source.version != destination.version:
            raise ValueError(f"{identifier}: source/destination IP versions differ")


def analyze(policy):
    """Return findings for the explicit, limited JSON rule model."""
    validate(policy)
    findings = []
    if policy["default_action"] == "allow":
        findings.append({
            "rule_id": None, "code": "DEFAULT_ALLOW", "severity": "HIGH",
            "detail": "Policy fallback action is allow; verify explicit least-privilege boundaries.",
        })
    for rule in policy["rules"]:
        source = ipaddress.ip_network(rule["source"], strict=True)
        destination = ipaddress.ip_network(rule["destination"], strict=True)
        if (rule["action"] == "allow" and source.prefixlen == 0
                and destination.prefixlen == 0 and rule["protocol"] == "any"):
            findings.append({
                "rule_id": rule["id"], "code": "ANY_TO_ANY_ALLOW", "severity": "CRITICAL",
                "detail": (f"Allows all protocols between all IPv{source.version} "
                           "addresses; verify intent and scope."),
            })
        if (rule["action"] == "allow" and source.prefixlen == 0
                and rule["protocol"] == "tcp" and rule["port"] in ADMIN_TCP_PORTS):
            findings.append({
                "rule_id": rule["id"],
                "code": "UNRESTRICTED_ADMIN_SOURCE",
                "severity": "HIGH",
                "detail": (f"TCP/{rule['port']} is allowed from all IPv{source.version} "
                           "addresses; review source restrictions."),
            })

    return {"policy": policy["name"], "rule_count": len(policy["rules"]),
            "findings": findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "iptables-save"), default="json",
                        help="Input format (default: illustrative JSON)")
    parser.add_argument("--report-format", choices=("json", "html", "csv"), default="json",
                        help="Output format (default: JSON)")
    parser.add_argument("--output", type=Path,
                        help="Save a new report file; existing files are not overwritten")
    parser.add_argument("policy", type=Path, help="Local policy file")
    args = parser.parse_args(argv)
    try:
        contents = args.policy.read_text(encoding="utf-8")
        policy = (json.loads(contents) if args.format == "json"
                  else parse_iptables_save(contents))
        report = analyze(policy)
        if args.format == "iptables-save":
            shadows = shadowed_by_prior_rule(policy["rules"])
            combined = combined_shadowed_by_prior_rules(policy["rules"], shadows)
            partial = partially_shadowed_by_prior_rules(policy["rules"], shadows, combined)
            report["findings"] = [finding for finding in report["findings"]
                                  if finding["rule_id"] not in shadows
                                  and finding["rule_id"] not in combined]
            for rule_id, earlier_id in shadows.items():
                report["findings"].append({
                    "rule_id": rule_id, "code": "SHADOWED_RULE", "severity": "INFO",
                    "covering_rule_ids": [earlier_id],
                    "detail": (f"{earlier_id} matches all traffic for this later rule; "
                               "it cannot be reached in this INPUT model."),
                })
            for rule_id, covering_ids in combined.items():
                names = (" and ".join(covering_ids) if len(covering_ids) == 2
                         else ", ".join(covering_ids[:-1]) + ", and " + covering_ids[-1])
                report["findings"].append({
                    "rule_id": rule_id, "code": "COMBINED_SHADOWED_RULE", "severity": "INFO",
                    "covering_rule_ids": covering_ids,
                    "detail": (f"{names} jointly match all traffic for this later rule; "
                               "it cannot be reached in this INPUT model."),
                })
            for rule_id, overlap in partial.items():
                report["findings"].append({
                    "rule_id": rule_id, "code": "PARTIALLY_SHADOWED_RULE", "severity": "INFO",
                    **overlap,
                    "detail": ("Earlier terminating INPUT rules match part, but not all, "
                               "of this rule's traffic; review redundant matches and rule order."),
                })
            input_order = {rule["id"]: index for index, rule in enumerate(policy["rules"])}
            report["findings"].sort(key=lambda item: input_order.get(item["rule_id"], -1))
            report["scope"] = ("Exact single/combined shadowing and partial overlap checked "
                               "for supported IPv4 INPUT; real reachability not evaluated")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid policy: {exc}", file=sys.stderr)
        return 2

    if args.report_format == "html":
        rendered = render_html(report)
    elif args.report_format == "csv":
        rendered = render_csv(report)
    else:
        rendered = json.dumps(report, indent=2) + "\n"
    try:
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            with args.output.open("x", encoding="utf-8", newline="") as destination:
                destination.write(rendered)
    except OSError as exc:
        print(f"Cannot save report: {exc}", file=sys.stderr)
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
