"""Limited first-match analysis of already validated INPUT rule objects."""

from ipaddress import ip_network


def _covers(earlier, later):
    """Whether one earlier terminating rule matches the later rule's full set."""
    if not ip_network(later["source"]).subnet_of(ip_network(earlier["source"])):
        return False
    if not ip_network(later["destination"]).subnet_of(ip_network(earlier["destination"])):
        return False
    if earlier["protocol"] == "any":
        return True
    return (earlier["protocol"] == later["protocol"]
            and earlier["port"] == later["port"])


def shadowed_by_prior_rule(rules):
    """Return later rule ID -> first single earlier covering terminal rule ID."""
    shadows = {}
    for index, later in enumerate(rules):
        for earlier in rules[:index]:
            if _covers(earlier, later):
                shadows[later["id"]] = earlier["id"]
                break
    return shadows
