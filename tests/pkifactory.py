"""Minimal PKI factory for tests: builds P-256 / ECDSA-SHA256 certs with
fine-grained control over extensions, validity and signing keys."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import DNSName, NameConstraints, SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from cryptography.x509.oid import NameOID

from x509path.certwrap import Cert, wrap

UTC = _dt.timezone.utc
NOT_BEFORE = _dt.datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = _dt.datetime(2030, 1, 1, tzinfo=UTC)
VERIFY_AT = _dt.datetime(2026, 6, 15, 12, tzinfo=UTC)

_server_ku = dict(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=None,
    decipher_only=None,
)
_ca_ku = dict(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=None,
    decipher_only=None,
)


def p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def cn(name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


@dataclass
class Issued:
    cert: Cert
    key: object


def issue(
    subject_cn: str,
    issuer_cert: Optional[Cert],
    issuer_key,
    *,
    subject_key=None,
    ca: bool = False,
    path_len: Optional[int] = None,
    server_auth: bool = True,
    eku_oids: Optional[Sequence] = None,
    san_dns: Iterable[str] = (),
    san_other: Sequence = (),
    san_critical: bool = False,
    permitted: Iterable[str] = (),
    excluded: Iterable[str] = (),
    nc_other_permitted: Sequence = (),
    nc_other_excluded: Sequence = (),
    not_before: _dt.datetime = NOT_BEFORE,
    not_after: _dt.datetime = NOT_AFTER,
    serial: Optional[int] = None,
    extra_extensions: Sequence[Tuple[x509.ExtensionType, bool]] = (),
    sign_key=None,
    sign_hash=hashes.SHA256(),
    omit_ku: bool = False,
    custom_ku: Optional[x509.KeyUsage] = None,
    omit_bc: bool = False,
    omit_eku: bool = False,
    self_subject: Optional[str] = None,
) -> "Issued":
    """Issue a certificate.

    ``issuer_cert`` supplies the issuer DN (None => self-issued DN).
    ``sign_key`` overrides the key used to sign (used to create a
    wrong-key / same-DN edge). ``self_subject`` forces the subject DN while
    the issuer DN still tracks ``issuer_cert`` (for self-issued nodes whose
    DN must equal the predecessor).
    """
    key = subject_key or p256_key()
    subject_name = cn(self_subject if self_subject is not None else subject_cn)
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject_name

    serial_value = serial if serial is not None else x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial_value)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if not omit_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_len), critical=True
        )
    if not omit_ku:
        if custom_ku is not None:
            builder = builder.add_extension(custom_ku, critical=True)
        else:
            ku = x509.KeyUsage(**(_ca_ku if ca else _server_ku))
            builder = builder.add_extension(ku, critical=True)
    if not omit_eku:
        if eku_oids is not None:
            oids = list(eku_oids)
        elif server_auth:
            oids = [EKU.SERVER_AUTH]
        else:
            oids = []
        if oids:
            builder = builder.add_extension(x509.ExtendedKeyUsage(oids), critical=False)

    san_entries: List[x509.GeneralName] = [DNSName(d) for d in san_dns]
    san_entries.extend(san_other)
    if san_entries:
        builder = builder.add_extension(
            SubjectAlternativeName(san_entries), critical=san_critical
        )

    permitted_names: List[x509.GeneralName] = [DNSName(d) for d in permitted]
    permitted_names.extend(nc_other_permitted)
    excluded_names: List[x509.GeneralName] = [DNSName(d) for d in excluded]
    excluded_names.extend(nc_other_excluded)
    if permitted_names or excluded_names:
        builder = builder.add_extension(
            NameConstraints(
                permitted_subtrees=permitted_names or None,
                excluded_subtrees=excluded_names or None,
            ),
            critical=True,
        )

    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)

    signing_key = sign_key if sign_key is not None else issuer_key
    cert = builder.sign(private_key=signing_key, algorithm=sign_hash)
    return Issued(cert=wrap(cert), key=key)


def root(cn_name: str = "Root R", *, not_after: _dt.datetime = NOT_AFTER) -> Issued:
    key = p256_key()
    issued = issue(
        cn_name,
        issuer_cert=None,
        issuer_key=key,
        subject_key=key,
        ca=True,
        path_len=None,
        omit_eku=True,
        not_after=not_after,
    )
    return issued
