"""Thin, explicit wrapper around parsed certificates.

cryptography is used only for:
  * DER/PEM parsing,
  * the ECDSA P-256 / SHA-256 signature arithmetic on one edge,
  * primitive field access.

It is never used as a full path validator; every acceptance decision in this
project is made in code under :mod:`x509path.rules` and :mod:`x509path.validate`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def _der(obj) -> bytes:
    return obj.public_bytes(Encoding.DER)


@dataclass(frozen=True)
class Cert:
    """A parsed certificate together with its canonical DER digest."""

    x509: x509.Certificate
    der: bytes
    sha256: str

    @property
    def subject(self) -> x509.Name:
        return self.x509.subject

    @property
    def issuer(self) -> x509.Name:
        return self.x509.issuer

    @property
    def is_self_issued(self) -> bool:
        """RFC 5280 4.2.1.9: self-issued iff subject DN == issuer DN."""
        return self.x509.subject == self.x509.issuer

    @property
    def is_self_signed(self) -> bool:
        """self-issued AND the signature verifies under its own public key."""
        return self.is_self_issued and verifies_signature(self, self)


def wrap(cert: x509.Certificate) -> Cert:
    der = _der(cert)
    return Cert(x509=cert, der=der, sha256=hashlib.sha256(der).hexdigest())


def load_cert_file(path: str) -> List[Cert]:
    """Load every certificate found in one file.

    Supports DER (one cert) and PEM (one or more concatenated certs).
    """
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return [wrap(x509.load_der_x509_certificate(data))]
    except ValueError:
        pass
    certs = x509.load_pem_x509_certificates(data)
    if not certs:
        raise ValueError(f"no certificates found in {path}")
    return [wrap(c) for c in certs]


def is_p256_key(cert: Cert) -> bool:
    key = cert.x509.public_key()
    return isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"


def is_ecdsa_sha256(cert: Cert) -> bool:
    alg = cert.x509.signature_algorithm_oid
    return alg == x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256


def verifies_signature(child: Cert, issuer_cert: Cert) -> bool:
    """Verify one edge: ``issuer_cert``'s key signs ``child``.

    The issuer must carry a usable P-256 key; cryptography performs only the
    ECDSA verification arithmetic.  Issuer/name binding is checked separately
    by :func:`directly_issued_by`.
    """
    issuer_key = issuer_cert.x509.public_key()
    if not isinstance(issuer_key, ec.EllipticCurvePublicKey):
        return False
    if issuer_key.curve.name != "secp256r1":
        return False
    if not is_p256_key(child):
        return False
    if not is_ecdsa_sha256(child):
        return False
    try:
        issuer_key.verify(
            child.x509.signature,
            child.x509.tbs_certificate_bytes,
            ec.ECDSA(ec.hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def directly_issued_by(child: Cert, issuer_cert: Cert) -> bool:
    """RFC 5280 6.1.3(a)(1): name binding plus cryptographic verification."""
    if child.issuer != issuer_cert.subject:
        return False
    return verifies_signature(child, issuer_cert)


def private_pkcs8_der(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
