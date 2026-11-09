"""Limited first-match analysis of already validated INPUT rule objects."""

from ipaddress import ip_network

from ports import port_bounds, port_fields

MAX_UNCOVERED_REGIONS = 4096


def _protocol_covers(earlier, later):
    if earlier["protocol"] == "any":
        return True
    if earlier["protocol"] != later["protocol"]:
        return False
    earlier_start, earlier_end = port_bounds(earlier)
    later_start, later_end = port_bounds(later)
    return earlier_start <= later_start and later_end <= earlier_end


def _covers(earlier, later):
    """Whether one earlier terminating rule matches the later rule's full set."""
    if not ip_network(later["source"]).subnet_of(ip_network(earlier["source"])):
        return False
    if not ip_network(later["destination"]).subnet_of(ip_network(earlier["destination"])):
        return False
    return _protocol_covers(earlier, later)


def shadowed_by_prior_rule(rules):
    """Return later rule ID -> first single earlier covering terminal rule ID."""
    shadows = {}
    for index, later in enumerate(rules):
        for earlier in rules[:index]:
            if _covers(earlier, later):
                shadows[later["id"]] = earlier["id"]
                break
    return shadows


def _subtract_region(region, covering_region):
    """Subtract a source-CIDR x destination-CIDR x inclusive-port region."""
    source, destination, (start, end) = region
    cover_source, cover_destination, (cover_start, cover_end) = covering_region
    if (not source.overlaps(cover_source) or not destination.overlaps(cover_destination)
            or end < cover_start or cover_end < start):
        return [region]

    common_source = cover_source if cover_source.subnet_of(source) else source
    common_destination = (cover_destination if cover_destination.subnet_of(destination)
                          else destination)
    common_start, common_end = max(start, cover_start), min(end, cover_end)
    remaining = []
    if source != common_source:
        remaining.extend((piece, destination, (start, end))
                         for piece in source.address_exclude(common_source))
    if destination != common_destination:
        remaining.extend((common_source, piece, (start, end))
                         for piece in destination.address_exclude(common_destination))
    if start < common_start:
        remaining.append((common_source, common_destination, (start, common_start - 1)))
    if common_end < end:
        remaining.append((common_source, common_destination, (common_end + 1, end)))
    return remaining


def _rule_region(rule):
    return ip_network(rule["source"]), ip_network(rule["destination"]), port_bounds(rule)


def covering_prior_rule_ids(later, prior_rules):
    """Return contributing IDs only when predecessors cover the entire rule.

    Specific TCP/UDP rules cannot fully cover an any-protocol candidate. Keep
    their protocol distinction separate from the modeled destination ports.
    """
    uncovered = [_rule_region(later)]
    contributors = []
    for earlier in prior_rules:
        if earlier["protocol"] not in {"any", later["protocol"]}:
            continue
        covering = _rule_region(earlier)
        remaining = []
        for region in uncovered:
            remaining.extend(_subtract_region(region, covering))
            if len(remaining) > MAX_UNCOVERED_REGIONS:
                raise ValueError("INPUT shadow coverage too complex; no partial report produced")
        if remaining != uncovered:
            contributors.append(earlier["id"])
        uncovered = remaining
        if not uncovered:
            return contributors
    return []


def combined_shadowed_by_prior_rules(rules, single_shadows):
    """Find complete union coverage by 2+ earlier terminal rules.

    Returns later ID -> contributing earlier IDs, in original order. Abort when
    exact disjoint CIDR/port partitioning exceeds the fixed complexity limit.
    """
    combined = {}
    for index, later in enumerate(rules):
        if later["id"] in single_shadows:
            continue
        contributors = covering_prior_rule_ids(later, rules[:index])
        if len(contributors) > 1:
            combined[later["id"]] = contributors
    return combined


def partially_shadowed_by_prior_rules(rules, single_shadows, combined_shadows):
    """Identify non-fully-covered later rules with earlier overlapping matches.

    An example describes one actual intersection, not the whole redundant
    region. Ignore earlier rules already fully shadowed by other predecessors.
    """
    fully_shadowed = set(single_shadows) | set(combined_shadows)
    networks = [(ip_network(rule["source"]), ip_network(rule["destination"]))
                for rule in rules]
    partial = {}
    for index, later in enumerate(rules):
        if later["id"] in fully_shadowed:
            continue
        overlapping_ids = []
        example = None
        later_source, later_destination = networks[index]
        for earlier_index in range(index):
            earlier = rules[earlier_index]
            if earlier["id"] in fully_shadowed:
                continue
            if (earlier["protocol"] != "any" and later["protocol"] != "any"
                    and earlier["protocol"] != later["protocol"]):
                continue
            earlier_start, earlier_end = port_bounds(earlier)
            later_start, later_end = port_bounds(later)
            common_start, common_end = max(earlier_start, later_start), min(earlier_end, later_end)
            if common_start > common_end:
                continue
            earlier_source, earlier_destination = networks[earlier_index]
            if not (earlier_source.overlaps(later_source)
                    and earlier_destination.overlaps(later_destination)):
                continue
            overlapping_ids.append(earlier["id"])
            if example is None:
                protocol = (earlier["protocol"] if later["protocol"] == "any"
                            else later["protocol"])
                example = {
                    "source": str(earlier_source if earlier_source.subnet_of(later_source)
                                  else later_source),
                    "destination": str(earlier_destination if earlier_destination.subnet_of(later_destination)
                                       else later_destination),
                    "protocol": protocol,
                    **({"port": None} if protocol == "any"
                       else port_fields(common_start, common_end)),
                }
        if overlapping_ids:
            partial[later["id"]] = {"overlapping_rule_ids": overlapping_ids,
                                    "overlap_example": example}
    return partial
