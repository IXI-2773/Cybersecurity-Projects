"""Conservative, offline adapter for IPv4 iptables-save -t filter INPUT exports.

Unsupported INPUT rules are rejected, never silently omitted. The adapter
does not evaluate packet reachability, rule shadowing, or other chains.
"""

import re
import shlex
from ipaddress import ip_network


COUNTERS = re.compile(r"^\[\d+:\d+\]$")


def _input_rule(line, line_number):
    tokens = shlex.split(line)
    if tokens[:2] != ["-A", "INPUT"]:
        raise ValueError(f"line {line_number}: invalid INPUT rule")
    options = {}
    for index in range(2, len(tokens), 2):
        if index + 1 >= len(tokens):
            raise ValueError(f"line {line_number}: incomplete option")
        key, value = tokens[index:index + 2]
        if key not in {"-s", "-d", "-p", "-j", "--dport", "-m"} or key in options:
            raise ValueError(f"line {line_number}: unsupported or repeated option {key}")
        options[key] = value

    protocol = options.get("-p", "all")
    if protocol not in {"all", "tcp", "udp"}:
        raise ValueError(f"line {line_number}: unsupported protocol {protocol}")
    if "-m" in options and options["-m"] != protocol:
        raise ValueError(f"line {line_number}: unsupported match module")
    target = options.get("-j")
    if target not in {"ACCEPT", "DROP", "REJECT"}:
        raise ValueError(f"line {line_number}: unsupported jump target {target}")
    if protocol == "all":
        if "--dport" in options:
            raise ValueError(f"line {line_number}: port without TCP/UDP")
        port = None
    else:
        if "--dport" not in options or not options["--dport"].isdigit():
            raise ValueError(f"line {line_number}: TCP/UDP requires one numeric destination port")
        port = int(options["--dport"])

    source = options.get("-s", "0.0.0.0/0")
    destination = options.get("-d", "0.0.0.0/0")
    if ip_network(source, strict=True).version != 4 or ip_network(destination, strict=True).version != 4:
        raise ValueError(f"line {line_number}: iptables-save mode only supports IPv4")

    return {
        "id": f"INPUT:L{line_number}",
        "action": "allow" if target == "ACCEPT" else "deny",
        "source": source,
        "destination": destination,
        "protocol": "any" if protocol == "all" else protocol,
        "port": port,
    }


def parse_iptables_save(contents):
    """Normalize the supported subset to the original JSON policy schema."""
    in_filter = False
    finished = False
    input_policy = None
    rules = []
    for line_number, raw in enumerate(contents.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "*filter" and not in_filter and not finished:
            in_filter = True
            continue
        if line == "COMMIT" and in_filter:
            in_filter = False
            finished = True
            continue
        if not in_filter:
            raise ValueError(f"line {line_number}: expected one complete *filter table")
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) != 3 or not COUNTERS.fullmatch(parts[2]):
                raise ValueError(f"line {line_number}: invalid chain declaration")
            chain, default, _ = parts
            if chain == "INPUT":
                if input_policy is not None or default not in {"ACCEPT", "DROP"}:
                    raise ValueError(f"line {line_number}: invalid INPUT default policy")
                input_policy = "allow" if default == "ACCEPT" else "deny"
        elif line.startswith("-A "):
            if line.split(maxsplit=2)[1] == "INPUT":
                if input_policy is None:
                    raise ValueError(f"line {line_number}: INPUT rule before chain declaration")
                rules.append(_input_rule(line, line_number))
            # Other chains are outside the declared review scope.
        else:
            raise ValueError(f"line {line_number}: unsupported export syntax")

    if not finished or input_policy is None:
        raise ValueError("missing complete filter table, INPUT policy or COMMIT")
    return {"name": "iptables-save IPv4 filter INPUT", "default_action": input_policy,
            "rules": rules}
