"""Mixed dNSName / iPAddress GeneralName handling for IP verification.

DNS mode (see :mod:`x509path.validate`) keeps the DNS-only profile.  IP
mode uses this module instead: a leaf SAN may mix dNSName and iPAddress
entries, and CA name constraints may mix dNSName and iPAddress subtrees.

Boundaries enforced here:

* the GeneralName *type* decides the kind of a name — a dNSName that
  merely looks like an address (``192.0.2.10``) is a DNS name, never an
  IP identity, and an iPAddress is never a DNS name;
* constraint state is tracked per name form: permitted subtrees of one
  form never restrict another form, and a form for which no permitted
  subtree was ever seen stays unrestricted;
* IPv4 and IPv6 are distinct families and are never converted into each
  other — an IPv4 CIDR neither permits nor excludes an IPv6 address;
* exclusions always win over permissions.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.x509.oid import ExtensionOID as OID

from .certwrap import Cert
from .dnsnames import DnsConstraints, parse_dns_name, validate_strict_dns

IpAddressT = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IpNetworkT = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# One SAN entry: ("dns", lowercased strict name) or ("ip", address object).
SanName = Tuple[str, object]


def parse_ip_literal(text: str) -> IpAddressT:
    """Parse the exact, unscoped IP literal given to ``--ip-address``.

    Rejects ports, brackets, zone/scope IDs, prefixes/subnets and any
    surrounding whitespace.  Returns the address object, whose ``str()``
    is the canonical display form (dotted quad / compressed IPv6).  The
    two families are kept distinct; no mapped or translated form is ever
    invented.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("IP address must be a non-empty literal")
    if text != text.strip():
        raise ValueError(f"IP address has surrounding whitespace: {text!r}")
    if "%" in text:
        raise ValueError(f"IP address must not carry a zone/scope id: {text!r}")
    if "/" in text:
        raise ValueError(
            f"IP address must be a single address, not a subnet: {text!r}"
        )
    if text.startswith("[") or text.endswith("]"):
        raise ValueError(f"IP address must not be bracketed: {text!r}")
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"invalid IP address literal {text!r}: {exc}") from exc


def _extension(cert: Cert, oid):
    try:
        return cert.x509.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def extract_mixed_san(
    cert: Cert, required: bool
) -> Tuple[Optional[Tuple[SanName, ...]], Optional[str]]:
    """SAN extraction under the mixed DNS/IP profile.

    Returns ``(names, error)`` where each name is a ``(kind, value)`` pair
    tagged by the GeneralName *type*.  Only dNSName and iPAddress entries
    are accepted; iPAddress entries must be single addresses, dNSName
    entries must be strict ASCII DNS.  With ``required`` a missing or
    entry-less SAN is an error (leaf rule); otherwise it yields ``()``.
    """
    san = _extension(cert, OID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        if required:
            return None, "server certificate lacks subjectAltName"
        return (), None
    names: List[SanName] = []
    for general_name in san:
        if isinstance(general_name, x509.DNSName):
            value = general_name.value
            if parse_dns_name(value) is None:
                return None, f"non-ASCII dNSName in subjectAltName: {value!r}"
            try:
                names.append(("dns", validate_strict_dns(value)))
            except ValueError as exc:
                return None, str(exc)
        elif isinstance(general_name, x509.IPAddress):
            value = general_name.value
            if not isinstance(
                value, (ipaddress.IPv4Address, ipaddress.IPv6Address)
            ):
                return None, (
                    "iPAddress in subjectAltName is not a single address: "
                    f"{value!r}"
                )
            names.append(("ip", value))
        else:
            return None, (
                "subjectAltName contains a disallowed general name "
                f"({type(general_name).__name__}); only dNSName and "
                "iPAddress accepted"
            )
    if required and not names:
        return None, "subjectAltName contains no dNSName or iPAddress entries"
    return tuple(names), None


def _network_intersection(
    a: IpNetworkT, b: IpNetworkT
) -> Optional[IpNetworkT]:
    """Intersection of two CIDR ranges, or ``None`` when disjoint.

    Two same-family CIDR blocks either are disjoint or one contains the
    other, so the intersection — when it exists — is the more specific
    block.  Different families never intersect.
    """
    if a.version != b.version or not a.overlaps(b):
        return None
    return a if a.prefixlen >= b.prefixlen else b


def _prune_networks(networks: Tuple[IpNetworkT, ...]) -> Tuple[IpNetworkT, ...]:
    """Drop ranges already covered by another range in the collection."""
    result = []
    for i, net in enumerate(networks):
        if any(
            i != j
            and net != other
            and net.version == other.version
            and net.subnet_of(other)
            for j, other in enumerate(networks)
        ):
            continue
        result.append(net)
    return tuple(result)


def _sorted_networks(networks: Tuple[IpNetworkT, ...]) -> List[IpNetworkT]:
    return sorted(
        networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen)
    )


@dataclass(frozen=True)
class IpConstraints:
    """Accumulated permitted/excluded IP subtrees (CIDR ranges).

    Mirrors :class:`DnsConstraints` semantics: ``permitted=None`` means
    the IP name form is unrestricted, ``permitted=()`` means the
    intersection of permitted ranges is empty and no address is allowed.
    """

    permitted: Optional[tuple] = None
    excluded: tuple = ()

    def merge(self, other: "IpConstraints") -> "IpConstraints":
        # Permitted ranges are intersected across CAs (alternatives within
        # one CA stay alternatives); excluded ranges are unioned.
        if self.permitted is None:
            permitted = other.permitted
        elif other.permitted is None:
            permitted = self.permitted
        else:
            candidates: List[IpNetworkT] = []
            for p in self.permitted:
                for q in other.permitted:
                    intersection = _network_intersection(p, q)
                    if intersection is not None:
                        candidates.append(intersection)
            permitted = _prune_networks(tuple(dict.fromkeys(candidates)))
        return IpConstraints(
            permitted=permitted,
            excluded=self.excluded
            + tuple(e for e in other.excluded if e not in self.excluded),
        )

    def is_empty(self) -> bool:
        return self.permitted is None and not self.excluded

    def violation(self, address: IpAddressT) -> Optional[str]:
        # ``in`` is family-safe: a v4 address is never contained in a v6
        # range and vice versa, so the families stay unconverted.
        for excl in self.excluded:
            if address in excl:
                return f"IP address {address} excluded by subtree {excl}"
        if self.permitted is not None and not any(
            address in p for p in self.permitted
        ):
            permitted = [str(p) for p in _sorted_networks(self.permitted)]
            return (
                f"IP address {address} not within permitted subtrees "
                f"{permitted!r}"
            )
        return None


@dataclass(frozen=True)
class MixedNameConstraints:
    """Per-name-form constraint state accumulated along a chain.

    dNSName and iPAddress subtrees accumulate independently: permitted
    subtrees of one form never restrict names of the other form, and a
    form with no permitted subtree stays unrestricted.
    """

    dns: DnsConstraints = DnsConstraints()
    ip: IpConstraints = IpConstraints()

    def merge(self, other: "MixedNameConstraints") -> "MixedNameConstraints":
        return MixedNameConstraints(
            dns=self.dns.merge(other.dns), ip=self.ip.merge(other.ip)
        )

    def is_empty(self) -> bool:
        return self.dns.is_empty() and self.ip.is_empty()

    def violation(self, kind: str, value) -> Optional[str]:
        if kind == "dns":
            return self.dns.violation(value)
        return self.ip.violation(value)


def _dns_constraint_entry(value: str, label: str) -> Tuple[Optional[str], Optional[str]]:
    """Normalize one dNSName constraint entry (same rules as DNS mode)."""
    if parse_dns_name(value) is None:
        return None, (
            f"non-ASCII dNSName in name constraints {label} subtree: {value!r}"
        )
    text = value.strip().lower()
    if text:
        try:
            if text.startswith("."):
                validate_strict_dns(text[1:])
            else:
                validate_strict_dns(text)
        except ValueError as exc:
            return None, str(exc)
    return text, None


def extract_mixed_name_constraints(
    cert: Cert,
) -> Tuple[Optional[MixedNameConstraints], Optional[str]]:
    """Extract mixed dNSName/iPAddress name constraints from a CA.

    ``(None, None)`` means the extension is absent.  Any GeneralName type
    other than dNSName/iPAddress, a non-ASCII or malformed dNSName, or an
    iPAddress that is not an address range rejects the certificate.
    """
    nc = _extension(cert, OID.NAME_CONSTRAINTS)
    if nc is None:
        return None, None

    dns_permitted: List[str] = []
    dns_excluded: List[str] = []
    ip_permitted: List[IpNetworkT] = []
    ip_excluded: List[IpNetworkT] = []
    for label, tree, dns_acc, ip_acc in (
        ("permitted", nc.permitted_subtrees, dns_permitted, ip_permitted),
        ("excluded", nc.excluded_subtrees, dns_excluded, ip_excluded),
    ):
        for general_name in tree or ():
            if isinstance(general_name, x509.DNSName):
                text, err = _dns_constraint_entry(general_name.value, label)
                if err is not None:
                    return None, err
                dns_acc.append(text)
            elif isinstance(general_name, x509.IPAddress):
                value = general_name.value
                if not isinstance(
                    value, (ipaddress.IPv4Network, ipaddress.IPv6Network)
                ):
                    return None, (
                        f"iPAddress in name constraints {label} subtree is "
                        f"not an address range (CIDR): {value!r}"
                    )
                ip_acc.append(value)
            else:
                return None, (
                    f"name constraints {label} subtree contains a disallowed "
                    f"general name ({type(general_name).__name__}); only "
                    "dNSName and iPAddress accepted"
                )

    return (
        MixedNameConstraints(
            dns=DnsConstraints(
                permitted=tuple(dns_permitted) or None,
                excluded=tuple(dns_excluded),
            ),
            ip=IpConstraints(
                permitted=tuple(ip_permitted) or None,
                excluded=tuple(ip_excluded),
            ),
        ),
        None,
    )
