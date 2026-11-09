"""Shared inclusive-port representation for already validated rule objects."""


def port_bounds(rule):
    """Return the modeled interval; protocol matching is handled separately."""
    if rule["protocol"] == "any":
        return 1, 65535
    return rule["port"], rule.get("port_end", rule["port"])


def port_fields(start, end):
    """Keep singleton ports backward compatible; add an end only for a range."""
    fields = {"port": start}
    if end != start:
        fields["port_end"] = end
    return fields
