"""Name conversion and network tests for IP certificate requests."""

import ipaddress
from cryptography import x509
from cryptography.x509.oid import ExtensionOID as OID
from .dnsnames import constraint_matches


def parse_ip(text):
    if not isinstance(text, str) or "%" in text or text != text.strip():
        raise ValueError("IP address must be an unscoped literal")
    return text


def extension(cert, oid):
    try:
        return cert.x509.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def san_names(cert, required=False):
    san = extension(cert, OID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        if required:
            raise ValueError("server certificate lacks subjectAltName")
        return []
    return [
        ("ip", str(name.value))
        for name in san
        if isinstance(name, (x509.DNSName, x509.IPAddress))
    ]


def constraints(cert):
    nc = extension(cert, OID.NAME_CONSTRAINTS)
    if nc is None:
        return None
    return [str(name.value) for name in nc.permitted_subtrees or []], [
        str(name.value) for name in nc.excluded_subtrees or []
    ]


def matches(kind, name, bound):
    if "/" not in bound:
        return constraint_matches(bound, str(name))
    try:
        address = ipaddress.ip_address(name)
        network = ipaddress.ip_network(bound)
        width = network.max_prefixlen
        mask = ((1 << width) - 1) ^ ((1 << (width - network.prefixlen)) - 1)
        return int(address) & mask == int(network.network_address)
    except ValueError:
        return False


class NamePolicy:
    def __init__(self):
        self.permitted = []
        self.excluded = []

    def add(self, group):
        if group is not None:
            self.permitted, self.excluded = group

    def violation(self, names):
        for kind, name in names:
            if self.permitted and not any(
                matches(kind, name, bound) for bound in self.permitted
            ):
                return f"name {name} outside issuer permitted subtrees"
        return None
