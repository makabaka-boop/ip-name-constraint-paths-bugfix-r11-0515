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
* extra/
    server-org.pem      - leaf www.good.example.org for the "bad" demo
    anchor.pin           - SHA-256 hex of the anchor DER
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

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

    write("anchor.pem", anchor.cert)
    write("cross-root.pem", cross.cert)
    write("intermediates/bridge.pem", bridge.cert)
    write("intermediates/issuing-good.pem", issuing_good.cert)
    write("intermediates/issuing-bad.pem", issuing_bad.cert)
    write("intermediates/cross-issuing.pem", cross_issuing.cert)
    write("intermediates/rollover-old.pem", rollover_old.cert)
    write("intermediates/rollover-new.pem", rollover_new.cert)
    write("server.pem", server.cert)
    write("extra/server-org.pem", server_org.cert)
    (OUT / "anchor.pin").write_text(anchor.cert.sha256 + "\n", encoding="ascii")

    print(f"sample PKI written to {OUT}")
    print(f"anchor SHA-256(DER) pin: {anchor.cert.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
