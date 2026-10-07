"""ASCII DNS-name parsing and RFC 5280 name-constraint matching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

# RFC 1035 2.3.1: labels [A-Za-z0-9-], not starting/ending with '-',
# label 1..63 octets, total 255 or fewer.  Everything must be ASCII.
_LABEL = __import__("re").compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def parse_dns_name(raw: object) -> Optional[str]:
    """Return a validated ASCII DNS name, or ``None`` if not DNS/ASCII.

    cryptography yields ``str`` for dNSName values; non-ASCII (e.g. IDN or
    other GeneralName types handled by callers) is rejected by returning
    ``None`` after the ASCII probe (callers distinguish type themselves).
    """
    if not isinstance(raw, str):
        return None
    try:
        raw.encode("ascii")
    except UnicodeEncodeError:
        return None
    return raw


def validate_strict_dns(value: str) -> str:
    """Validate an ASCII DNS name used in a SAN or as lookup input.

    Wildcards, a trailing root dot, empty labels and non-LDH characters are
    rejected.  Returns the lower-cased canonical form.
    """
    text = parse_dns_name(value)
    if text is None:
        raise ValueError(f"non-ASCII DNS name: {value!r}")
    if (
        not text
        or any(ch.isspace() for ch in text)
        or text.endswith(".")
        or text.startswith(".")
        or "*" in text
    ):
        raise ValueError(
            f"illegal DNS name (empty, leading/trailing dot, whitespace or "
            f"wildcard): {value!r}"
        )
    labels = text.split(".")
    if len(text) > 255:
        raise ValueError(f"DNS name too long: {value!r}")
    for label in labels:
        if not _LABEL.fullmatch(label):
            raise ValueError(f"illegal DNS label {label!r} in {value!r}")
    return text.lower()


def _labels(name: str) -> List[str]:
    return name.lower().split(".")


def in_domain(child: str, parent: str) -> bool:
    """True if ``child`` equals ``parent`` or is a sub-domain of it."""
    c, p = _labels(child), _labels(parent)
    if len(c) < len(p):
        return False
    # Compare the trailing |p| labels of child with parent's labels.
    return c[len(c) - len(p) :] == p


def _constraint_within(inner: str, outer: str) -> bool:
    """True if the set of names matched by ``inner`` is a subset of those
    matched by ``outer`` (both RFC 5280 DNS constraint cones)."""
    a, b = inner.strip().lower(), outer.strip().lower()
    if b == "":
        return True
    if a == "":
        return False
    if a.startswith("."):
        a_base, a_sub_only = a[1:], True
    else:
        a_base, a_sub_only = a, False
    if b.startswith("."):
        b_base, b_sub_only = b[1:], True
    else:
        b_base, b_sub_only = b, False
    if not in_domain(a_base, b_base):
        return False
    # Inner cone must not include the apex if the outer excludes it.
    if b_sub_only and not a_sub_only and a_base == b_base:
        return False
    return True


def _prune_redundant(constraints: tuple) -> tuple:
    """Drop any constraint whose matched set is already covered by another
    (wider or equal) constraint in the collection, keeping narrower ones."""
    result = []
    for i, c in enumerate(constraints):
        if any(
            i != j and c != other and _constraint_within(c, other)
            for j, other in enumerate(constraints)
        ):
            continue
        result.append(c)
    return tuple(result)


def constraint_matches(constraint: str, name: str) -> bool:
    """RFC 5280 4.2.1.10 DNS name matching.

    * ``example.com`` matches the host and every sub-domain;
    * ``.example.com`` (leading dot) matches sub-domains only, never the
      host itself, per RFC 5280 4.2.1.10;
    * the empty string matches any DNS name.
    """
    c = constraint.strip().lower()
    if c == "":
        return True
    if c.startswith("."):
        base = c[1:]
        if not base:
            return False
        # Sub-domains only: strictly more labels than the base and within it.
        return in_domain(name, base) and len(_labels(name)) > len(_labels(base))
    return in_domain(name, c)


@dataclass(frozen=True)
class DnsConstraints:
    """Accumulated permitted/excluded DNS subtrees.

    Only dNSName entries may appear in a name constraints extension; any
    other GeneralName type rejects the certificate at profile-check time.
    """

    permitted: tuple = ()
    excluded: tuple = ()

    def merge(self, other: "DnsConstraints") -> "DnsConstraints":
        # RFC 5280 6.1.4(h): permitted subtrees are intersected while
        # excluded subtrees are unioned as the path is walked top-down.
        #
        # Each constraint is a suffix cone (RFC 5280 4.2.1.10 DNS rules).
        # A cone from the new state survives intersection only when it lies
        # inside every previous permitted cone; keeping all surviving
        # narrowest cones preserves exactly the matched-name intersection
        # (a leading-dot cone adds nothing beyond a contained plain cone).
        if not self.permitted:
            permitted = tuple(other.permitted)
        elif not other.permitted:
            permitted = tuple(self.permitted)
        else:
            # A constraint from either state survives when its cone lies
            # within EVERY constraint of the other state.  Broader but still
            # intersecting constraints must be retained (e.g. the apex of an
            # outer cone stays reachable via the outer entry), then pruned if
            # they are redundant given narrower entries from the same side.
            candidates = tuple(
                p
                for p in self.permitted
                if all(_constraint_within(p, q) for q in other.permitted)
            ) + tuple(
                p
                for p in other.permitted
                if all(_constraint_within(p, q) for q in self.permitted)
            )
            permitted = _prune_redundant(tuple(dict.fromkeys(candidates)))
        return DnsConstraints(
            permitted=permitted,
            excluded=self.excluded
            + tuple(e for e in other.excluded if e not in self.excluded),
        )

    def is_empty(self) -> bool:
        return not self.permitted and not self.excluded

    def allows(self, name: str) -> bool:
        n = name.lower()
        for excl in self.excluded:
            if constraint_matches(excl, n):
                return False
        if not self.permitted:
            return True
        return any(constraint_matches(p, n) for p in self.permitted)

    def violation(self, name: str) -> Optional[str]:
        n = name.lower()
        for excl in self.excluded:
            if constraint_matches(excl, n):
                return f"DNS name {n!r} excluded by subtree {excl!r}"
        if self.permitted and not any(constraint_matches(p, n) for p in self.permitted):
            return (
                f"DNS name {n!r} not within permitted subtrees "
                f"{sorted(self.permitted)!r}"
            )
        return None
