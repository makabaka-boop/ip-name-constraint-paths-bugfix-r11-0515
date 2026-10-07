#!/usr/bin/env python3
"""Generate the bundled offline sample PKI under examples/pki/.

The sample exercises every structural feature the validator supports:

* anchor.pem            - the pinned trust root (P-256, self-signed)
* cross-root.pem        - a second root cross-certified by the anchor
* intermediates/
    issuing-good.pem    - "Issuing CA" key A, permitted good.example.com
    issuing-bad.pem     - "Issuing CA" key B (same DN!), permitted *.org
    cross-issuing.pem   - same key as issuing-good, signed by cross-root
    rollover-old.pem    - "Rollover CA" with the old key (pathLen=0)
    rollover-new.pem    - self-issued key-change cert, new key, same DN
* server.pem            - leaf for www.good.example.com (signed by new key)
* server-ip.pem         - leaf with mixed SAN: DNS www.good.example.com,
                          IPv4 192.0.2.10, IPv6 2001:db8::10
* intermediates/
    issuing-ip.pem      - "IP Issuing CA": permits good.example.com,
                          192.0.2.0/24 and 2001:db8::/32; excludes the
                          host 192.0.2.66/32
* extra/
    server-org.pem      - leaf www.good.example.org for the "bad" demo
    server-ip-excluded.pem - leaf whose SAN holds the excluded 192.0.2.66
    server-numeric-dns.pem - leaf whose dNSName "192.0.2.10" only *looks*
                          like an address (DNS identity, never an IP one)
    anchor.pin           - SHA-256 hex of the anchor DER
"""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

from pkifactory import (  # noqa: E402
    NOT_AFTER,
    NOT_BEFORE,
    issue,
    p256_key,
    root,
)

OUT = Path(__file__).resolve().parent.parent / "examples" / "pki"


def pem(cert) -> bytes:
    raw = cert.x509 if hasattr(cert, "x509") else cert
    return raw.public_bytes(Encoding.PEM)


def write(rel: str, cert) -> None:
    path = OUT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem(cert))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    anchor = root("Example Offline Anchor")
    cross = root("Example Cross Root")

    # The anchor cross-certifies the second root under its own DN.
    bridge = issue(
        "Example Cross Root",
        anchor.cert,
        anchor.key,
        subject_key=cross.key,
        ca=True,
    )

    # Two same-DN issuing CAs with different keys and different scopes.
    good_key = p256_key()
    issuing_good = issue(
        "Issuing CA",
        anchor.cert,
        anchor.key,
        subject_key=good_key,
        ca=True,
        path_len=0,
        permitted=["good.example.com"],
        excluded=["revoked.good.example.com"],
    )
    bad_key = p256_key()
    issuing_bad = issue(
        "Issuing CA",
        anchor.cert,
        anchor.key,
        subject_key=bad_key,
        ca=True,
        path_len=0,
        permitted=["good.example.org"],
    )
    # The good issuing key is also certified by the cross root.
    cross_issuing = issue(
        "Issuing CA",
        cross.cert,
        cross.key,
        subject_key=good_key,
        ca=True,
        path_len=0,
        permitted=["good.example.com"],
    )

    # Self-issued key rollover for a distinct CA ("Rollover CA").
    old_key = p256_key()
    rollover_old = issue(
        "Rollover CA",
        anchor.cert,
        anchor.key,
        subject_key=old_key,
        ca=True,
        path_len=0,
        permitted=["good.example.com"],
    )
    new_key = p256_key()
    rollover_new = issue(
        "Rollover CA",
        rollover_old.cert,
        old_key,
        subject_key=new_key,
        ca=True,
        path_len=0,
        permitted=["good.example.com"],
        self_subject="Rollover CA",
    )

    # The demo leaf is issued by the post-rollover key.
    server = issue(
        "www.good.example.com",
        rollover_new.cert,
        new_key,
        ca=False,
        san_dns=["www.good.example.com"],
    )
    server_org = issue(
        "www.good.example.org",
        issuing_bad.cert,
        bad_key,
        ca=False,
        san_dns=["www.good.example.org"],
    )

    # IP-capable issuing CA: mixed dNSName/iPAddress permitted subtrees and
    # one excluded IPv4 host route.
    ip_key = p256_key()
    issuing_ip = issue(
        "IP Issuing CA",
        anchor.cert,
        anchor.key,
        subject_key=ip_key,
        ca=True,
        path_len=0,
        permitted=["good.example.com"],
        nc_other_permitted=[
            x509.IPAddress(ipaddress.ip_network("192.0.2.0/24")),
            x509.IPAddress(ipaddress.ip_network("2001:db8::/32")),
        ],
        nc_other_excluded=[
            x509.IPAddress(ipaddress.ip_network("192.0.2.66/32")),
        ],
    )
    # Leaf with a mixed SAN: one DNS name plus one address per family.
    server_ip = issue(
        "www.good.example.com",
        issuing_ip.cert,
        ip_key,
        ca=False,
        san_dns=["www.good.example.com"],
        san_other=[
            x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::10")),
        ],
    )
    # Leaf whose SAN carries the excluded address 192.0.2.66.
    server_ip_excluded = issue(
        "excluded.good.example.com",
        issuing_ip.cert,
        ip_key,
        ca=False,
        san_dns=["excluded.good.example.com"],
        san_other=[x509.IPAddress(ipaddress.ip_address("192.0.2.66"))],
    )
    # A dNSName that merely looks like an IPv4 address: a DNS identity,
    # never an IP one.  Issued directly under the anchor (no constraints).
    server_numeric_dns = issue(
        "192.0.2.10",
        anchor.cert,
        anchor.key,
        ca=False,
        san_dns=["192.0.2.10"],
    )

    write("anchor.pem", anchor.cert)
    write("cross-root.pem", cross.cert)
    write("intermediates/bridge.pem", bridge.cert)
    write("intermediates/issuing-good.pem", issuing_good.cert)
    write("intermediates/issuing-bad.pem", issuing_bad.cert)
    write("intermediates/issuing-ip.pem", issuing_ip.cert)
    write("intermediates/cross-issuing.pem", cross_issuing.cert)
    write("intermediates/rollover-old.pem", rollover_old.cert)
    write("intermediates/rollover-new.pem", rollover_new.cert)
    write("server.pem", server.cert)
    write("server-ip.pem", server_ip.cert)
    write("extra/server-org.pem", server_org.cert)
    write("extra/server-ip-excluded.pem", server_ip_excluded.cert)
    write("extra/server-numeric-dns.pem", server_numeric_dns.cert)
    (OUT / "anchor.pin").write_text(anchor.cert.sha256 + "\n", encoding="ascii")

    print(f"sample PKI written to {OUT}")
    print(f"anchor SHA-256(DER) pin: {anchor.cert.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
