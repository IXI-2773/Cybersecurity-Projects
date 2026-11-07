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
    parser.add_argument("policy", type=Path, help="Local illustrative policy JSON file")
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        report = analyze(policy)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid policy: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
