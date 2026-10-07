"""End-to-end path validation tests.

Scenario coverage required by the delivery:
  1. same-CN different-key CAs;
  2. first-bad-then-good cross-signed chains;
  3. nested permitted/excluded DNS name constraints;
  4. self-issued key-change intermediates (pathLen counting, fake roots, rings);
  5. permutation invariance of the trust conclusion and display path;
  6. profile rejection (wildcard/IP SAN, EKU, critical extensions, ...).
"""

from __future__ import annotations

import ipaddress
import itertools

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from cryptography.x509.oid import NameOID

from x509path import validate_paths
from x509path.certwrap import wrap
from x509path.cli import run as cli_run

from pkifactory import NOT_AFTER, NOT_BEFORE, VERIFY_AT, cn, issue, p256_key, root


def failure_text(report) -> str:
    parts = []
    for f in report.failures:
        parts.append(f"layer {f.layer} {f.failing_cert.sha256[:12]}: {f.reason}")
    for d in report.dead_ends:
        parts.append(f"dead-end {d.tip.sha256[:12]}: {d.reason}")
    return " | ".join(parts)


def pem(cert) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    raw = (
        cert.x509
        if hasattr(cert, "x509")
        else (
            cert.cert.x509
            if hasattr(cert, "cert") and hasattr(cert.cert, "x509")
            else cert
        )
    )
    return raw.public_bytes(Encoding.PEM)


def write_tree(tmp_path, r, intermediates, leaf):
    anchor = tmp_path / "anchor.pem"
    anchor.write_bytes(pem(r.cert))
    int_paths = []
    for i, c in enumerate(intermediates):
        p = tmp_path / f"int{i}.pem"
        p.write_bytes(pem(c.cert if hasattr(c, "cert") else c))
        int_paths.append(str(p))
    server = tmp_path / "leaf.pem"
    server.write_bytes(pem(leaf.cert if hasattr(leaf, "cert") else leaf))
    return str(anchor), int_paths, str(server)


def run_validation(leaf, pool, r, name, moment=VERIFY_AT):
    pool_certs = [c.cert if hasattr(c, "cert") else c for c in pool]
    leaf_cert = leaf.cert if hasattr(leaf, "cert") else leaf
    return validate_paths(leaf_cert, pool_certs, r.cert, moment, name)


# --------------------------------------------------------------------------
# 1. Same common name, different keys.
# --------------------------------------------------------------------------


def test_same_name_different_keys_chooses_signing_ca():
    r = root()
    ca_key_a, ca_key_b = p256_key(), p256_key()
    ca_a = issue(
        "Shared CA Name", r.cert, r.key, subject_key=ca_key_a, ca=True, path_len=0
    )
    ca_b = issue(
        "Shared CA Name", r.cert, r.key, subject_key=ca_key_b, ca=True, path_len=0
    )
    leaf = issue(
        "www.example.com", ca_b.cert, ca_key_b, ca=False, san_dns=["www.example.com"]
    )

    report = run_validation(leaf, [ca_a, ca_b], r, "www.example.com")
    assert report.trusted, failure_text(report)
    digests = [c.sha256 for c in report.chosen_chain.certs]
    assert digests == [r.cert.sha256, ca_b.cert.sha256, leaf.cert.sha256]


def test_same_name_wrong_key_only_is_not_trusted_and_reports_dead_end():
    r = root()
    ca_key_a, ca_key_b = p256_key(), p256_key()
    ca_a = issue("Shared CA Name", r.cert, r.key, subject_key=ca_key_a, ca=True)
    # Leaf metadata names the shared issuer, signed by the absent key B.
    leaf = issue(
        "www.example.com", ca_a.cert, ca_key_b, ca=False, san_dns=["www.example.com"]
    )

    report = run_validation(leaf, [ca_a], r, "www.example.com")
    assert not report.trusted
    assert report.failures == []
    assert any(
        "different key" in d.reason or "bad signature" in d.reason
        for d in report.dead_ends
    )


def test_same_name_ca_cannot_bypass_domain_constraint_of_other_chain():
    r = root()
    ca_key_a = p256_key()
    ca_a = issue(
        "Shared Issuer",
        r.cert,
        r.key,
        subject_key=ca_key_a,
        ca=True,
        path_len=0,
        permitted=["example.org"],
    )
    ca_key_b = p256_key()
    ca_b = issue(
        "Shared Issuer", r.cert, r.key, subject_key=ca_key_b, ca=True, path_len=0
    )
    leaf_a = issue(
        "www.example.org", ca_a.cert, ca_key_a, ca=False, san_dns=["www.example.org"]
    )
    leaf_b = issue(
        "www.example.com", ca_b.cert, ca_key_b, ca=False, san_dns=["www.example.com"]
    )

    pool = [ca_a, ca_b]
    assert run_validation(leaf_a, pool, r, "www.example.org").trusted
    assert run_validation(leaf_b, pool, r, "www.example.com").trusted

    # The .org leaf cannot be validated as .com (name absent) nor via B.
    assert not run_validation(leaf_a, pool, r, "www.example.com").trusted

    # A .com leaf signed by A violates A's permitted subtree.
    leaf_bad = issue(
        "www.example.com", ca_a.cert, ca_key_a, ca=False, san_dns=["www.example.com"]
    )
    rep = run_validation(leaf_bad, [ca_a], r, "www.example.com")
    assert not rep.trusted
    assert rep.failures and "permitted" in rep.failures[0].reason


# --------------------------------------------------------------------------
# 2. Cross-signed chains, first-bad-then-good.
# --------------------------------------------------------------------------


def test_cross_sign_first_bad_then_good_orders_independent_of_input():
    r = root()
    r2 = root("New Root R2")

    x_key = p256_key()
    x_direct = issue(
        "Intermediate X",
        r.cert,
        r.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        permitted=["example.com"],
    )
    x_cross = issue(
        "Intermediate X", r2.cert, r2.key, subject_key=x_key, ca=True, path_len=0
    )
    bridge = issue("New Root R2", r.cert, r.key, subject_key=r2.key, ca=True)

    # .com leaf: both chains complete and valid, in every pool ordering.
    leaf_com = issue(
        "www.example.com", x_direct.cert, x_key, ca=False, san_dns=["www.example.com"]
    )
    expected = None
    for perm in itertools.permutations([x_direct, x_cross, bridge]):
        rep = run_validation(leaf_com, list(perm), r, "www.example.com")
        assert rep.trusted, failure_text(rep)
        seq = tuple(c.sha256 for c in rep.chosen_chain.certs)
        expected = expected or seq
        assert seq == expected  # unique display path regardless of order

    # Only the constrained chain present + a .org name: rejected.
    leaf_org = issue(
        "www.example.org", x_direct.cert, x_key, ca=False, san_dns=["www.example.org"]
    )
    bad = run_validation(leaf_org, [x_direct], r, "www.example.org")
    assert not bad.trusted
    assert "permitted" in bad.failures[0].reason

    # Add the unconstrained cross chain ("先坏后好"): now trusted, any order.
    for perm in itertools.permutations([x_direct, x_cross, bridge]):
        rep = run_validation(leaf_org, list(perm), r, "www.example.org")
        assert rep.trusted, failure_text(rep)


def test_cross_sign_all_candidates_bad_lists_each_first_failure():
    r = root()
    r2 = root("New Root R2")
    x_key = p256_key()
    x_direct = issue(
        "Intermediate X",
        r.cert,
        r.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        permitted=["example.com"],
    )
    x_cross = issue(
        "Intermediate X",
        r2.cert,
        r2.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        excluded=["example.org"],
    )
    bridge = issue("New Root R2", r.cert, r.key, subject_key=r2.key, ca=True)
    leaf = issue(
        "www.example.org", x_direct.cert, x_key, ca=False, san_dns=["www.example.org"]
    )

    report = run_validation(leaf, [x_direct, x_cross, bridge], r, "www.example.org")
    assert not report.trusted
    # Two complete candidate chains; the name-constraint violation is
    # surfaced on the leaf (RFC 5280 applies constraints to subordinates),
    # but each candidate reports its own first failure and its own path.
    assert len(report.failures) == 2
    reasons = " ".join(f.reason for f in report.failures)
    assert "permitted" in reasons and "excluded" in reasons
    chain_x = {tuple(c.sha256 for c in f.chain.certs) for f in report.failures}
    direct_seq = (r.cert.sha256, x_direct.cert.sha256, leaf.cert.sha256)
    cross_seq = (
        r.cert.sha256,
        bridge.cert.sha256,
        x_cross.cert.sha256,
        leaf.cert.sha256,
    )
    assert direct_seq in chain_x
    assert cross_seq in chain_x
    assert all(f.failing_cert.sha256 == leaf.cert.sha256 for f in report.failures)


# --------------------------------------------------------------------------
# 3. Nested domain restrictions.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "c1perm,c1excl,c2perm,c2excl,name,expected,word",
    [
        (["example.com"], [], [".example.com"], [], "host.example.com", True, None),
        (["example.com"], [], [".example.com"], [], "example.com", False, "permitted"),
        ([], [], [], ["bad.example.com"], "bad.example.com", False, "excluded"),
        ([], [], [], ["bad.example.com"], "ok.example.com", True, None),
        (
            [],
            ["corp.example.com"],
            ["corp.example.com"],
            [],
            "x.corp.example.com",
            False,
            "excluded",
        ),
        (
            ["example.com"],
            [],
            ["www.example.com"],
            [],
            "api.example.com",
            False,
            "permitted",
        ),
        (["example.com"], [], ["www.example.com"], [], "www.example.com", True, None),
        ([], [], [".example.com"], [], "example.com", False, "permitted"),
        # exclusion of a parent zone blocks nested hosts too
        ([], ["example.com"], [], [], "deep.a.example.com", False, "excluded"),
    ],
)
def test_nested_name_constraints(c1perm, c1excl, c2perm, c2excl, name, expected, word):
    r = root()
    ca1 = issue("Outer CA", r.cert, r.key, ca=True, permitted=c1perm, excluded=c1excl)
    ca2 = issue(
        "Inner CA",
        ca1.cert,
        ca1.key,
        ca=True,
        path_len=0,
        permitted=c2perm,
        excluded=c2excl,
    )
    leaf = issue(name, ca2.cert, ca2.key, ca=False, san_dns=[name])

    report = run_validation(leaf, [ca1, ca2], r, name)
    assert report.trusted is expected, failure_text(report)
    if not expected:
        assert any(word in f.reason for f in report.failures)


def test_non_dns_name_constraint_is_rejected():
    r = root()
    ip = x509.IPAddress(ipaddress.ip_network("10.0.0.0/8"))
    ca = issue("IP NC CA", r.cert, r.key, ca=True, nc_other_permitted=[ip])
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "non-DNS" in report.failures[0].reason


def test_multiple_san_names_all_constrained():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True, excluded=["bad.example.com"])
    leaf = issue(
        "host",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["good.example.com", "bad.example.com"],
    )
    report = run_validation(leaf, [ca], r, "good.example.com")
    assert not report.trusted
    assert "excluded" in report.failures[0].reason


# --------------------------------------------------------------------------
# 4. Self-issued key-change nodes.
# --------------------------------------------------------------------------


def test_self_issued_key_rollover_followed_and_not_counted_in_pathlen():
    r = root()
    old_key = p256_key()
    ca_old = issue("CA-X", r.cert, r.key, subject_key=old_key, ca=True, path_len=0)
    new_key = p256_key()
    ca_new = issue(
        "CA-X",
        ca_old.cert,
        old_key,
        subject_key=new_key,
        ca=True,
        path_len=0,
        self_subject="CA-X",
    )
    assert ca_new.cert.is_self_issued
    assert not ca_new.cert.is_self_signed  # different key

    leaf = issue(
        "www.example.com", ca_new.cert, new_key, ca=False, san_dns=["www.example.com"]
    )
    # Input intentionally unordered; the rollover node must be threaded in.
    report = run_validation(leaf, [ca_new, ca_old], r, "www.example.com")
    assert report.trusted, failure_text(report)
    assert [c.sha256 for c in report.chosen_chain.certs] == [
        r.cert.sha256,
        ca_old.cert.sha256,
        ca_new.cert.sha256,
        leaf.cert.sha256,
    ]


def test_pathlen_counts_non_self_issued_below():
    r = root()
    top_key = p256_key()
    top = issue("Top CA", r.cert, r.key, subject_key=top_key, ca=True, path_len=0)
    sub_key = p256_key()
    sub = issue("Sub CA", top.cert, top_key, subject_key=sub_key, ca=True)
    leaf = issue(
        "www.example.com", sub.cert, sub_key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [top, sub], r, "www.example.com")
    assert not report.trusted
    assert "pathLenConstraint" in report.failures[0].reason
    assert report.failures[0].failing_cert.sha256 == top.cert.sha256


def test_certificate_ring_is_terminated_and_valid_edge_still_trusted():
    r = root()
    k1, k2 = p256_key(), p256_key()
    a = issue("Ring CA", r.cert, r.key, subject_key=k1, ca=True)
    b = issue("Ring CA", a.cert, k1, subject_key=k2, ca=True, self_subject="Ring CA")
    a_ring = issue(
        "Ring CA", b.cert, k2, subject_key=k1, ca=True, self_subject="Ring CA"
    )
    leaf = issue("www.example.com", a.cert, k1, ca=False, san_dns=["www.example.com"])
    # Ring noise present, but root -> a(k1) -> leaf is valid.
    report = run_validation(leaf, [b, a_ring, a], r, "www.example.com")
    assert report.trusted, failure_text(report)

    # Pure ring with no anchor-reachable member cannot terminate.
    leaf2 = issue(
        "ring.example.com", b.cert, k2, ca=False, san_dns=["ring.example.com"]
    )
    report2 = run_validation(leaf2, [b, a_ring], r, "ring.example.com")
    assert not report2.trusted
    assert report2.dead_ends
    assert any("ring" in d.reason for d in report2.dead_ends)


def test_self_signed_lookalike_is_not_a_trust_root():
    r = root("The Anchor")
    fake = root("The Anchor")  # same DN, own key, self-signed
    assert fake.cert.is_self_signed and fake.cert.sha256 != r.cert.sha256

    ca_key = p256_key()
    ca = issue("Sub CA", fake.cert, fake.key, subject_key=ca_key, ca=True)
    leaf = issue(
        "www.example.com", ca.cert, ca_key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [fake, ca], r, "www.example.com")
    assert not report.trusted
    assert report.failures == []
    assert report.dead_ends


# --------------------------------------------------------------------------
# 5. Permutation invariance across a larger random-shaped pool.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("winner", range(4))
def test_permutation_invariance_with_decoy_same_name_cas(winner):
    r = root()
    keys = [p256_key() for _ in range(4)]
    # All four share one DN; only `winner` signs the leaf.
    cas = [
        issue("Same Name CA", r.cert, r.key, subject_key=keys[i], ca=True, path_len=0)
        for i in range(4)
    ]
    leaf = issue(
        "www.example.com",
        cas[winner].cert,
        keys[winner],
        ca=False,
        san_dns=["www.example.com"],
    )
    expected = None
    for perm in itertools.permutations(cas):
        rep = run_validation(leaf, list(perm), r, "www.example.com")
        assert rep.trusted, failure_text(rep)
        seq = tuple(c.sha256 for c in rep.chosen_chain.certs)
        expected = expected or seq
        assert seq == expected
    assert cas[winner].cert.sha256 in expected


# --------------------------------------------------------------------------
# 6. Profile / RFC 5280 rejections.
# --------------------------------------------------------------------------


def test_anchor_signature_and_validity_are_not_evaluated():
    r_exp = root("Expired Anchor", not_after=NOT_BEFORE)
    ca = issue("CA", r_exp.cert, r_exp.key, ca=True, path_len=0)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r_exp, "www.example.com")
    assert report.trusted, failure_text(report)


def test_intermediate_validity_window_enforced():
    r = root()
    expired = issue("Expired CA", r.cert, r.key, ca=True, not_after=NOT_BEFORE)
    leaf = issue(
        "www.example.com",
        expired.cert,
        expired.key,
        ca=False,
        san_dns=["www.example.com"],
    )
    report = run_validation(leaf, [expired], r, "www.example.com")
    assert not report.trusted
    assert "expired" in report.failures[0].reason
    assert report.failures[0].failing_cert.sha256 == expired.cert.sha256


def test_leaf_not_yet_valid_enforced():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "future.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["future.example.com"],
        not_before=NOT_AFTER,
    )
    report = run_validation(leaf, [ca], r, "future.example.com")
    assert not report.trusted
    assert "not yet valid" in report.failures[0].reason


def test_wildcard_san_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "star.example.com", ca.cert, ca.key, ca=False, san_dns=["*.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "wildcard" in report.failures[0].reason


def test_ip_san_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "host.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["host.example.com"],
        san_other=[x509.IPAddress(ipaddress.ip_address("10.0.0.1"))],
    )
    report = run_validation(leaf, [ca], r, "host.example.com")
    assert not report.trusted
    assert "non-DNS" in report.failures[0].reason


def test_exact_dns_name_case_insensitive():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "WWW.Example.COM", ca.cert, ca.key, ca=False, san_dns=["WWW.Example.COM"]
    )
    assert run_validation(leaf, [ca], r, "www.example.com").trusted
    assert not run_validation(leaf, [ca], r, "other.example.com").trusted


def test_ca_missing_keycertsign_rejected():
    r = root()
    no_sign = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )
    ca = issue("Weak CA", r.cert, r.key, ca=True, custom_ku=no_sign)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "keyCertSign" in report.failures[0].reason


def test_leaf_without_digital_signature_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    encipher = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=None,
        decipher_only=None,
    )
    leaf = issue(
        "www.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.example.com"],
        custom_ku=encipher,
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "digitalSignature" in report.failures[0].reason


def test_intermediate_eku_without_serverauth_rejected():
    r = root()
    ca = issue("Email CA", r.cert, r.key, ca=True, eku_oids=[EKU.EMAIL_PROTECTION])
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "serverAuth" in report.failures[0].reason


def test_leaf_eku_must_contain_server_auth():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "www.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.example.com"],
        eku_oids=[EKU.CLIENT_AUTH],
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "serverAuth" in report.failures[0].reason


def test_unknown_critical_extension_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    unknown = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x01\x02\x03"
    )
    leaf = issue(
        "www.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.example.com"],
        extra_extensions=[(unknown, True)],
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "critical extension" in report.failures[0].reason


def test_leaf_basic_constraints_ca_true_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=True, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "cA=true" in report.failures[0].reason


def test_ca_without_basic_constraints_rejected():
    r = root()
    ca = issue("NoBC CA", r.cert, r.key, ca=True, omit_bc=True)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert "basicConstraints" in report.failures[0].reason


def test_non_ecdsa_rsa_leaf_rejected():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(cn("www.example.com"))
        .issuer_name(ca.cert.subject)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("www.example.com")]),
            critical=False,
        )
        .sign(ca.key, hashes.SHA256())
    )
    leaf = wrap(cert)
    # Edge exists cryptographically for name purposes? RSA leaf -> ECDSA CA:
    # builder cannot verify under our edge predicate (we require ECDSA child),
    # so it is a dead end and never a candidate.
    report = validate_paths(leaf, [ca.cert], r.cert, VERIFY_AT, "www.example.com")
    assert not report.trusted
    assert report.dead_ends and not report.failures


def test_tampered_wrong_signature_breaks_chain():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    other = p256_key()
    leaf = issue(
        "www.example.com", ca.cert, other, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [ca], r, "www.example.com")
    assert not report.trusted
    assert report.failures == []
    assert any(
        "different key" in d.reason or "bad signature" in d.reason
        for d in report.dead_ends
    )


def test_missing_intermediate_is_dead_end():
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    sub = issue("Sub", ca.cert, ca.key, ca=True)
    leaf = issue(
        "www.example.com", sub.cert, sub.key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [], r, "www.example.com")
    assert not report.trusted
    assert any("no certificate" in d.reason for d in report.dead_ends)


def test_long_chain_eight_intermediates_accepted():
    r = root()
    cas, keys = [], []
    prev_cert, prev_key = r.cert, r.key
    for i in range(8):
        k = p256_key()
        c = issue(f"Level {i}", prev_cert, prev_key, subject_key=k, ca=True)
        cas.append(c)
        keys.append(k)
        prev_cert, prev_key = c.cert, k
    leaf = issue(
        "www.example.com", cas[-1].cert, keys[-1], ca=False, san_dns=["www.example.com"]
    )
    import random

    rng = random.Random(42)
    for _ in range(5):
        pool = cas[:]
        rng.shuffle(pool)
        report = run_validation(leaf, pool, r, "www.example.com")
        assert report.trusted, failure_text(report)
        assert len(report.chosen_chain.certs) == 10


def test_pathlen_bound_halfway_down_a_deep_chain():
    r = root()
    # First intermediate pathLen=1 with two more non-self-issued CAs below
    # -> violation; a self-issued node would not count.
    k0 = p256_key()
    top = issue("Top", r.cert, r.key, subject_key=k0, ca=True, path_len=1)
    k1 = p256_key()
    mid = issue("Mid", top.cert, k0, subject_key=k1, ca=True)
    k2 = p256_key()
    low = issue("Low", mid.cert, k1, subject_key=k2, ca=True)
    leaf = issue("www.example.com", low.cert, k2, ca=False, san_dns=["www.example.com"])
    report = run_validation(leaf, [top, mid, low], r, "www.example.com")
    assert not report.trusted
    assert report.failures[0].failing_cert.sha256 == top.cert.sha256
    assert "pathLenConstraint=1" in report.failures[0].reason


def test_display_path_chosen_by_digest_order():
    r = root()
    r2 = root("Alt Root Cross")
    x_key = p256_key()
    x1 = issue("X", r.cert, r.key, subject_key=x_key, ca=True, path_len=0)
    x2 = issue("X", r2.cert, r2.key, subject_key=x_key, ca=True, path_len=0)
    bridge = issue("Alt Root Cross", r.cert, r.key, subject_key=r2.key, ca=True)
    leaf = issue(
        "www.example.com", x1.cert, x_key, ca=False, san_dns=["www.example.com"]
    )
    report = run_validation(leaf, [x1, x2, bridge], r, "www.example.com")
    assert report.trusted
    valid_sequences = []
    # The chosen path must equal the min digest tuple among all valid chains.
    from x509path import build_chains

    chains, _ = build_chains(leaf.cert, [x1.cert, x2.cert, bridge.cert], r.cert)
    good = []
    for ch in chains:
        from x509path.validate import validate_chain

        if validate_chain(ch, VERIFY_AT, "www.example.com") is None:
            good.append(tuple(c.sha256 for c in ch.certs))
    chosen = tuple(c.sha256 for c in report.chosen_chain.certs)
    assert chosen == min(good)
    assert len(good) >= 2


# --------------------------------------------------------------------------
# 7. CLI behavior.
# --------------------------------------------------------------------------


def _argv(paths, pin, name="www.example.com", extra=()):
    anchor, ints, server = paths
    argv = [
        "--anchor",
        anchor,
        "--anchor-pin",
        pin,
        "--server",
        server,
        "--at",
        "2026-06-15T12:00:00Z",
        "--dns-name",
        name,
    ]
    for p in ints:
        argv += ["--intermediates", p]
    argv += list(extra)
    return argv


def test_cli_trusted_json(tmp_path):
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True, path_len=0)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, [ca], leaf)
    import json
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_run(_argv(paths, r.cert.sha256, "WWW.Example.COM", extra=["--json"]))
    assert code == 0
    data = json.loads(buf.getvalue())
    assert data["trusted"] is True
    assert [p["position"] for p in data["display_path"]] == [0, 1, 2]
    assert data["display_path_digests"] == [
        r.cert.sha256,
        ca.cert.sha256,
        leaf.cert.sha256,
    ]


def test_cli_pin_mismatch_exit_2(tmp_path):
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, [ca], leaf)
    assert cli_run(_argv(paths, "00" * 32)) == 2


def test_cli_untrusted_exit_1_and_lists_failure(tmp_path):
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True, permitted=["example.org"])
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, [ca], leaf)
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_run(_argv(paths, r.cert.sha256))
    assert code == 1
    assert "NOT TRUSTED" in buf.getvalue()
    assert "permitted" in buf.getvalue()


def test_cli_more_than_eight_intermediates_exit_2(tmp_path):
    r = root()
    cas, keys = [], []
    prev_cert, prev_key = r.cert, r.key
    for i in range(9):
        k = p256_key()
        c = issue(f"CA{i}", prev_cert, prev_key, subject_key=k, ca=True)
        cas.append(c)
        keys.append(k)
        prev_cert, prev_key = c.cert, k
    leaf = issue(
        "www.example.com", cas[-1].cert, keys[-1], ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, cas, leaf)
    assert cli_run(_argv(paths, r.cert.sha256)) == 2


def test_cli_bad_time_exit_2(tmp_path):
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, [ca], leaf)
    argv = _argv(paths, r.cert.sha256)
    argv[argv.index("--at") + 1] = "2026-06-15 12:00:00"  # naive, rejected
    assert cli_run(argv) == 2


def test_cli_non_ascii_dns_name_exit_2(tmp_path):
    r = root()
    ca = issue("CA", r.cert, r.key, ca=True)
    leaf = issue(
        "www.example.com", ca.cert, ca.key, ca=False, san_dns=["www.example.com"]
    )
    paths = write_tree(tmp_path, r, [ca], leaf)
    argv = _argv(paths, r.cert.sha256, name="www.éxample.com")
    assert cli_run(argv) == 2
