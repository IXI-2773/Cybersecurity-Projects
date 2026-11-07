"""Limited first-match analysis of already validated INPUT rule objects."""

from ipaddress import ip_network

MAX_UNCOVERED_REGIONS = 4096


def _protocol_covers(earlier, later):
    return (earlier["protocol"] == "any"
            or (earlier["protocol"] == later["protocol"]
                and earlier["port"] == later["port"]))


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
    """Subtract an IPv4 CIDR rectangle; return disjoint remaining rectangles."""
    source, destination = region
    cover_source, cover_destination = covering_region
    if not source.overlaps(cover_source) or not destination.overlaps(cover_destination):
        return [region]

    common_source = cover_source if cover_source.subnet_of(source) else source
    common_destination = (cover_destination if cover_destination.subnet_of(destination)
                          else destination)
    remaining = []
    if source != common_source:
        remaining.extend((piece, destination) for piece in source.address_exclude(common_source))
    if destination != common_destination:
        remaining.extend((common_source, piece)
                         for piece in destination.address_exclude(common_destination))
    return remaining


def combined_shadowed_by_prior_rules(rules, single_shadows):
    """Find complete union coverage by 2+ earlier terminal rules.

    Returns later ID -> contributing earlier IDs, in original order. Abort when
    exact disjoint CIDR partitioning exceeds the fixed complexity limit.
    """
    combined = {}
    networks = [(ip_network(rule["source"]), ip_network(rule["destination"]))
                for rule in rules]
    for index, later in enumerate(rules):
        if later["id"] in single_shadows:
            continue
        uncovered = [networks[index]]
        contributors = []
        for earlier_index in range(index):
            earlier = rules[earlier_index]
            if not _protocol_covers(earlier, later):
                continue
            remaining = []
            for region in uncovered:
                remaining.extend(_subtract_region(region, networks[earlier_index]))
                if len(remaining) > MAX_UNCOVERED_REGIONS:
                    raise ValueError("INPUT shadow coverage too complex; no partial report produced")
            if remaining != uncovered:
                contributors.append(earlier["id"])
            uncovered = remaining
            if not uncovered:
                if len(contributors) > 1:
                    combined[later["id"]] = contributors
                break
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
            if not (_protocol_covers(earlier, later) or later["protocol"] == "any"):
                continue
            earlier_source, earlier_destination = networks[earlier_index]
            if not (earlier_source.overlaps(later_source)
                    and earlier_destination.overlaps(later_destination)):
                continue
            overlapping_ids.append(earlier["id"])
            if example is None:
                example = {
                    "source": str(earlier_source if earlier_source.subnet_of(later_source)
                                  else later_source),
                    "destination": str(earlier_destination if earlier_destination.subnet_of(later_destination)
                                       else later_destination),
                    "protocol": (earlier["protocol"] if later["protocol"] == "any"
                                 else later["protocol"]),
                    "port": earlier["port"] if later["protocol"] == "any" else later["port"],
                }
        if overlapping_ids:
            partial[later["id"]] = {"overlapping_rule_ids": overlapping_ids,
                                    "overlap_example": example}
    return partial
