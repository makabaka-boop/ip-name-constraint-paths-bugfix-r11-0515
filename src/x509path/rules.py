"""RFC 5280 acceptance rules for the restricted certificate profile.

Every check here operates on a single certificate (or accumulates name
constraints); none of them delegates to a complete path validator.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import ExtensionOID as OID

from .certwrap import Cert, is_ecdsa_sha256, is_p256_key
from .dnsnames import DnsConstraints, parse_dns_name, validate_strict_dns

# Extensions permitted to be marked critical in this restricted profile.
# Any other critical extension (policies, policy mappings/constraints,
# inhibitAnyPolicy, CRL distribution points, unknown/private OIDs, ...)
# rejects the certificate outright.
ALLOWED_CRITICAL = frozenset(
    {
        OID.BASIC_CONSTRAINTS,
        OID.KEY_USAGE,
        OID.EXTENDED_KEY_USAGE,
        OID.SUBJECT_ALTERNATIVE_NAME,
        OID.NAME_CONSTRAINTS,
    }
)

SERVER_AUTH = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
ANY_EKU = x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: Optional[str] = None

    @classmethod
    def fail(cls, reason: str) -> "CheckResult":
        return cls(False, reason)

    @classmethod
    def good(cls) -> "CheckResult":
        return cls(True, None)


def _extension(cert: Cert, oid):
    try:
        return cert.x509.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def check_common_profile(cert: Cert) -> CheckResult:
    """Version v3, P-256 key, ECDSA-with-SHA256 signature, critical-extension
    allowlist.  Applies to every non-anchor certificate in the chain."""
    if cert.x509.version != x509.Version.v3:
        return CheckResult.fail(
            f"certificate is {cert.x509.version.name}, only v3 accepted"
        )
    if not is_p256_key(cert):
        return CheckResult.fail("public key is not P-256 (secp256r1)")
    if not is_ecdsa_sha256(cert):
        return CheckResult.fail(
            "signature algorithm is not ecdsa-with-SHA256 "
            f"({cert.x509.signature_algorithm_oid.dotted_string})"
        )
    for ext in cert.x509.extensions:
        if ext.critical and ext.oid not in ALLOWED_CRITICAL:
            return CheckResult.fail(
                f"unknown or disallowed critical extension {ext.oid.dotted_string}"
            )
    return CheckResult.good()


def check_validity(cert: Cert, moment: _dt.datetime) -> CheckResult:
    if moment < cert.x509.not_valid_before_utc:
        return CheckResult.fail(
            "certificate not yet valid "
            f"(notBefore={cert.x509.not_valid_before_utc.isoformat()}, "
            f"verify at {moment.isoformat()})"
        )
    if moment > cert.x509.not_valid_after_utc:
        return CheckResult.fail(
            "certificate expired "
            f"(notAfter={cert.x509.not_valid_after_utc.isoformat()}, "
            f"verify at {moment.isoformat()})"
        )
    return CheckResult.good()


def check_basic_constraints(cert: Cert, is_leaf: bool) -> CheckResult:
    ext = _extension(cert, OID.BASIC_CONSTRAINTS)
    # RFC 5280 4.2.1.9: cA boolean defaults to false when absent.
    ca = bool(ext.value.ca) if ext is not None else False
    if is_leaf:
        if ca:
            return CheckResult.fail("server certificate has cA=true basicConstraints")
        return CheckResult.good()
    if ext is None or not ca:
        return CheckResult.fail("CA certificate lacks cA=true basicConstraints")
    return CheckResult.good()


def basic_constraints_path_len(cert: Cert) -> Optional[int]:
    ext = _extension(cert, OID.BASIC_CONSTRAINTS)
    if ext is None:
        return None
    return ext.value.path_length


def check_key_usage(cert: Cert, is_leaf: bool) -> CheckResult:
    ext = _extension(cert, OID.KEY_USAGE)
    # KeyUsage is required for the restricted profile so that purpose is
    # always explicit (RFC 5280 marks it optional for the leaf, but the
    # delivery specification demands KeyUsage enforcement at every layer).
    if ext is None:
        return CheckResult.fail("required keyUsage extension is absent")
    ku = ext.value
    if is_leaf:
        if not ku.digital_signature:
            return CheckResult.fail(
                "server certificate keyUsage does not assert digitalSignature"
            )
    else:
        if not ku.key_cert_sign:
            return CheckResult.fail(
                "CA certificate keyUsage does not assert keyCertSign"
            )
    return CheckResult.good()


def check_eku_server_auth(cert: Cert, is_leaf: bool) -> CheckResult:
    """Purpose constraints at each layer.

    * The leaf must be usable for id-kp-serverAuth (explicitly required by
      the delivery specification; id-anyEKU is NOT accepted on the leaf so a
      purpose cannot be silently broadened).
    * A CA carrying EKU constrains every subordinate chain; it must contain
      serverAuth (anyEKU on a CA is honored per RFC 5280 4.2.1.12).
    * A CA without EKU imposes no purpose restriction.
    """
    ext = _extension(cert, OID.EXTENDED_KEY_USAGE)
    if is_leaf:
        if ext is None:
            return CheckResult.fail(
                "server certificate lacks extendedKeyUsage serverAuth"
            )
        oids = list(ext.value)
        if SERVER_AUTH not in oids:
            return CheckResult.fail(
                "server certificate extendedKeyUsage does not contain serverAuth"
            )
        return CheckResult.good()
    if ext is None:
        return CheckResult.good()
    oids = list(ext.value)
    if SERVER_AUTH not in oids and ANY_EKU not in oids:
        return CheckResult.fail(
            "intermediate CA extendedKeyUsage does not permit serverAuth"
        )
    return CheckResult.good()


def extract_dns_names(cert: Cert) -> Tuple[Optional[Tuple[str, ...]], Optional[str]]:
    """Leaf SAN extraction under the DNS-only / ASCII-only profile.

    Returns (names, error).  SAN must be present, must contain at least one
    dNSName, must not contain any non-dNSName GeneralName, and every name
    must be strict ASCII.
    """
    ext = _extension(cert, OID.SUBJECT_ALTERNATIVE_NAME)
    if ext is None:
        return None, "server certificate lacks subjectAltName"
    san = ext.value
    names = []
    for general_name in san:
        if not isinstance(general_name, x509.DNSName):
            return None, (
                "subjectAltName contains a non-DNS general name "
                f"({type(general_name).__name__}); only dNSName accepted"
            )
    for name in san.get_values_for_type(x509.DNSName):
        if parse_dns_name(name) is None:
            return None, f"non-ASCII dNSName in subjectAltName: {name!r}"
        try:
            names.append(validate_strict_dns(name))
        except ValueError as exc:
            return None, str(exc)
    if not names:
        return None, "subjectAltName contains no dNSName entries"
    return tuple(names), None


def extract_name_constraints(
    cert: Cert,
) -> Tuple[Optional[DnsConstraints], Optional[str]]:
    """Extract DNS-only, ASCII-only name constraints from a CA certificate.

    ``None`` constraints means the extension is absent.  Any non-dNSName
    GeneralName in permitted or excluded subtrees rejects the certificate.
    """
    ext = _extension(cert, OID.NAME_CONSTRAINTS)
    if ext is None:
        return None, None
    nc = ext.value

    def _collect(tree, label: str):
        out = []
        for general_name in tree or ():
            if not isinstance(general_name, x509.DNSName):
                return None, (
                    f"name constraints {label} subtree contains non-DNS general "
                    f"name ({type(general_name).__name__}); only dNSName accepted"
                )
        for name in tree or ():
            value = name.value
            if parse_dns_name(value) is None:
                return None, (
                    f"non-ASCII dNSName in name constraints {label} subtree: "
                    f"{value!r}"
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
            out.append(text)
        return tuple(out), None

    permitted, err = _collect(nc.permitted_subtrees, "permitted")
    if err:
        return None, err
    excluded, err = _collect(nc.excluded_subtrees, "excluded")
    if err:
        return None, err
    return DnsConstraints(permitted=permitted, excluded=excluded), None
