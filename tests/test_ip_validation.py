"""End-to-end IP-address path validation tests (mixed DNS/IP profile).

Covers the IP delivery requirements:
  * canonical IPv6 handling — any legal notation of the same address;
  * GeneralName *type* decides identity — numeric dNSName is never an IP;
  * per-name-form constraint state — DNS and IP permitted subtrees do not
    restrict each other; IPv4 and IPv6 are never converted;
  * multi-layer accumulation — permitted intersected, excluded unioned and
    always winning, empty intersection means "nothing", not "anything";
  * every candidate chain judged independently — a legal alternative chain
    makes the conclusion independent of intermediate ordering;
  * self-issued key-change nodes — exempt from preceding constraints while
    their own constraints still bind descendants;
  * deterministic display path and identical canonical address / path in
    text and JSON output.
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import itertools
import json

import pytest
from cryptography import x509

from x509path import validate_paths
from x509path.cli import run as cli_run
from x509path.generalnames import (
    IpConstraints,
    MixedNameConstraints,
    parse_ip_literal,
)
from x509path.dnsnames import DnsConstraints
from x509path.ipvalidate import validate_ip_paths

from pkifactory import NOT_BEFORE, VERIFY_AT, issue, p256_key, root
from test_path_validation import failure_text, write_tree


def ip_san(*addrs):
    return [x509.IPAddress(ipaddress.ip_address(a)) for a in addrs]


def ip_nets(*nets):
    return [x509.IPAddress(ipaddress.ip_network(n)) for n in nets]


def run_ip(leaf, pool, r, address, moment=VERIFY_AT):
    pool_certs = [c.cert if hasattr(c, "cert") else c for c in pool]
    leaf_cert = leaf.cert if hasattr(leaf, "cert") else leaf
    return validate_ip_paths(leaf_cert, pool_certs, r.cert, moment, address)


def ip_ca(name, r, permitted_ip=(), excluded_ip=(), permitted_dns=(), **kw):
    return issue(
        name,
        r.cert,
        r.key,
        ca=True,
        permitted=permitted_dns,
        nc_other_permitted=ip_nets(*permitted_ip),
        nc_other_excluded=ip_nets(*excluded_ip),
        **kw,
    )


# --------------------------------------------------------------------------
# Canonical parsing of the requested literal.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "given,canonical",
    [
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::10", "2001:db8::10"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0010", "2001:db8::10"),
        ("2001:0db8:0:0:0:0:0:10", "2001:db8::10"),
        ("::1", "::1"),
    ],
)
def test_parse_ip_literal_canonicalizes(given, canonical):
    assert str(parse_ip_literal(given)) == canonical


@pytest.mark.parametrize(
    "bad",
    [
        "2001:db8::10/32",  # a subnet, not an address
        "192.0.2.0/24",
        "[2001:db8::10]",  # bracketed
        "192.0.2.10:443",  # port
        "fe80::1%eth0",  # zone/scope id
        " 192.0.2.10",  # whitespace
        "192.0.2.10 ",
        "",
        "not-an-ip",
        "www.example.com",
    ],
)
def test_parse_ip_literal_rejects(bad):
    with pytest.raises(ValueError):
        parse_ip_literal(bad)


# --------------------------------------------------------------------------
# Basic trust decisions over both address families.
# --------------------------------------------------------------------------


def ip_pki():
    r = root()
    ca = ip_ca(
        "IP CA",
        r,
        permitted_ip=["192.0.2.0/24", "2001:db8::/32"],
        excluded_ip=["192.0.2.66/32"],
        permitted_dns=["good.example.com"],
        path_len=0,
    )
    leaf = issue(
        "www.good.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.good.example.com"],
        san_other=ip_san("192.0.2.10", "2001:db8::10"),
    )
    return r, ca, leaf


def test_ip_v4_and_v6_trusted():
    r, ca, leaf = ip_pki()
    assert run_ip(leaf, [ca], r, "192.0.2.10").trusted
    assert run_ip(leaf, [ca], r, "2001:db8::10").trusted


def test_ip_v6_alternate_notation_same_conclusion():
    r, ca, leaf = ip_pki()
    report = run_ip(leaf, [ca], r, "2001:0DB8:0000:0000:0000:0000:0000:0010")
    assert report.trusted, failure_text(report)
    # The report carries the canonical form of the requested address.
    assert report.dns_name == "2001:db8::10"
    assert report.as_dict()["ip_address"] == "2001:db8::10"
    assert report.as_dict()["name_kind"] == "ip"


def test_ip_absent_from_san_rejected():
    r, ca, leaf = ip_pki()
    report = run_ip(leaf, [ca], r, "192.0.2.11")
    assert not report.trusted
    assert "not present" in report.failures[0].reason
    assert report.failures[0].failing_cert.sha256 == leaf.cert.sha256


def test_ip_excluded_address_rejected():
    r, ca, leaf = ip_pki()
    leaf66 = issue(
        "excluded.good.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["excluded.good.example.com"],
        san_other=ip_san("192.0.2.66"),
    )
    report = run_ip(leaf66, [ca], r, "192.0.2.66")
    assert not report.trusted
    assert "excluded" in report.failures[0].reason


# --------------------------------------------------------------------------
# Identity boundaries: name type and address family.
# --------------------------------------------------------------------------


def test_numeric_dns_name_is_not_an_ip_identity():
    r = root()
    # dNSName that merely looks like an IPv4 address, signed by the anchor.
    leaf = issue("192.0.2.10", r.cert, r.key, ca=False, san_dns=["192.0.2.10"])
    report = run_ip(leaf, [], r, "192.0.2.10")
    assert not report.trusted
    assert "not present" in report.failures[0].reason
    # ...while the very same string remains a perfectly valid DNS identity.
    dns_report = validate_paths(leaf.cert, [], r.cert, VERIFY_AT, "192.0.2.10")
    assert dns_report.trusted, failure_text(dns_report)


def test_ip_san_not_satisfied_by_other_family_or_dns():
    r = root()
    ca = ip_ca("CA", r, path_len=0)
    leaf = issue(
        "host",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["10.0.0.1"],  # numeric dNSName, still a DNS name
        san_other=ip_san("10.0.0.1"),
    )
    # The v4 address itself is fine ...
    assert run_ip(leaf, [ca], r, "10.0.0.1").trusted
    # ... but the IPv4-mapped IPv6 spelling is a different identity: the
    # families are never converted into each other.
    report = run_ip(leaf, [ca], r, "::ffff:10.0.0.1")
    assert not report.trusted
    assert "not present" in report.failures[0].reason


def test_ipv4_constraint_never_matches_ipv6_address():
    r = root()
    # Permitted v4 range whose bits also appear in the v6 address ::a00:1;
    # a family-blind mask comparison would wrongly admit it.
    ca = ip_ca("CA", r, permitted_ip=["10.0.0.0/8"], path_len=0)
    leaf = issue("v6host", ca.cert, ca.key, ca=False, san_other=ip_san("::a00:1"))
    report = run_ip(leaf, [ca], r, "::a00:1")
    assert not report.trusted
    assert "permitted" in report.failures[0].reason
    # And the v4 exclusion must not catch the v6 address either: with an
    # unrestricted permitted state the v6 address is accepted.
    ca2 = ip_ca("CA2", r, excluded_ip=["10.0.0.0/8"], path_len=0)
    leaf2 = issue("v6host", ca2.cert, ca2.key, ca=False, san_other=ip_san("::a00:1"))
    assert run_ip(leaf2, [ca2], r, "::a00:1").trusted


def test_permitted_of_one_name_form_does_not_restrict_the_other():
    r = root()
    # CA permits only a DNS subtree: IP addresses stay unrestricted.
    ca_dns = ip_ca("DNS CA", r, permitted_dns=["good.example.com"], path_len=0)
    leaf_ip = issue(
        "www.good.example.com",
        ca_dns.cert,
        ca_dns.key,
        ca=False,
        san_dns=["www.good.example.com"],
        san_other=ip_san("203.0.113.7"),
    )
    assert run_ip(leaf_ip, [ca_dns], r, "203.0.113.7").trusted

    # CA permits only an IP range: DNS names stay unrestricted.
    ca_ip = ip_ca("IP CA", r, permitted_ip=["192.0.2.0/24"], path_len=0)
    leaf_dns = issue(
        "anything.example.org",
        ca_ip.cert,
        ca_ip.key,
        ca=False,
        san_dns=["anything.example.org"],
        san_other=ip_san("192.0.2.10"),
    )
    assert run_ip(leaf_dns, [ca_ip], r, "192.0.2.10").trusted


# --------------------------------------------------------------------------
# Multi-layer accumulation.
# --------------------------------------------------------------------------


def test_permitted_ranges_intersect_across_cas():
    r = root()
    outer = ip_ca("Outer", r, permitted_ip=["192.0.2.0/24"])
    inner = issue(
        "Inner",
        outer.cert,
        outer.key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.0.2.0/25"),
    )
    leaf_in = issue("h", inner.cert, inner.key, ca=False, san_other=ip_san("192.0.2.66"))
    leaf_out = issue(
        "h", inner.cert, inner.key, ca=False, san_other=ip_san("192.0.2.200")
    )
    assert run_ip(leaf_in, [outer, inner], r, "192.0.2.66").trusted
    report = run_ip(leaf_out, [outer, inner], r, "192.0.2.200")
    assert not report.trusted
    assert "permitted" in report.failures[0].reason


def test_disjoint_permitted_intersection_permits_nothing():
    r = root()
    outer = ip_ca("Outer", r, permitted_ip=["10.0.0.0/8"])
    inner = issue(
        "Inner",
        outer.cert,
        outer.key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.168.0.0/16"),
    )
    leaf = issue("h", inner.cert, inner.key, ca=False, san_other=ip_san("10.0.0.1"))
    report = run_ip(leaf, [outer, inner], r, "10.0.0.1")
    assert not report.trusted
    assert "permitted" in report.failures[0].reason


def test_disjoint_dns_permitted_intersection_permits_nothing():
    # Same empty-intersection rule for the DNS name form (unit level).
    merged = DnsConstraints(permitted=("example.com",)).merge(
        DnsConstraints(permitted=("example.org",))
    )
    assert not merged.is_empty()
    assert not merged.allows("www.example.com")
    assert not merged.allows("anything.else.net")


def test_exclusion_unions_and_cannot_be_readmitted():
    r = root()
    outer = ip_ca("Outer", r, excluded_ip=["192.0.2.66/32"])
    inner = issue(
        "Inner",
        outer.cert,
        outer.key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.0.2.66/32"),  # re-admit attempt
    )
    leaf = issue("h", inner.cert, inner.key, ca=False, san_other=ip_san("192.0.2.66"))
    report = run_ip(leaf, [outer, inner], r, "192.0.2.66")
    assert not report.trusted
    assert "excluded" in report.failures[0].reason


def test_all_san_names_must_satisfy_constraints():
    r = root()
    ca = ip_ca("CA", r, excluded_ip=["192.0.2.66/32"], path_len=0)
    leaf = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_other=ip_san("192.0.2.10", "192.0.2.66"),
    )
    # The requested address itself is fine; the sibling SAN entry is not.
    report = run_ip(leaf, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "excluded" in report.failures[0].reason


def test_mixed_san_checked_per_name_form():
    r = root()
    ca = ip_ca(
        "CA",
        r,
        permitted_dns=["good.example.com"],
        permitted_ip=["192.0.2.0/24"],
        path_len=0,
    )
    # DNS entry outside the DNS cone, IP entry inside the IP range.
    leaf_bad_dns = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.other.example.org"],
        san_other=ip_san("192.0.2.10"),
    )
    report = run_ip(leaf_bad_dns, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "DNS name" in report.failures[0].reason
    # DNS entry inside, IP entry outside.
    leaf_bad_ip = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["www.good.example.com"],
        san_other=ip_san("198.51.100.9"),
    )
    report = run_ip(leaf_bad_ip, [ca], r, "198.51.100.9")
    assert not report.trusted
    assert "IP address" in report.failures[0].reason


# --------------------------------------------------------------------------
# Subordinate SANs and self-issued key-change nodes.
# --------------------------------------------------------------------------


def test_intermediate_san_is_constrained():
    r = root()
    outer = ip_ca("Outer", r, permitted_ip=["192.0.2.0/24"])
    # A non-self-issued intermediate whose own SAN falls outside the
    # permitted range: every subordinate SAN is constrained.
    mid = issue(
        "Mid",
        outer.cert,
        outer.key,
        ca=True,
        path_len=0,
        san_other=ip_san("10.0.0.1"),
    )
    leaf = issue("h", mid.cert, mid.key, ca=False, san_other=ip_san("192.0.2.10"))
    report = run_ip(leaf, [outer, mid], r, "192.0.2.10")
    assert not report.trusted
    assert report.failures[0].failing_cert.sha256 == mid.cert.sha256
    assert "permitted" in report.failures[0].reason


def test_self_issued_node_exempt_but_its_constraints_bind_descendants():
    r = root()
    outer = ip_ca("Outer", r, permitted_ip=["192.0.2.0/24"])
    old_key, new_key = p256_key(), p256_key()
    ca_old = issue("CA-X", outer.cert, outer.key, subject_key=old_key, ca=True)
    # Self-issued key-change node: its own SAN is outside the permitted
    # range (exempt, RFC 5280 6.1.4(h)), but it excludes one address for
    # everything below it.
    ca_new = issue(
        "CA-X",
        ca_old.cert,
        old_key,
        subject_key=new_key,
        ca=True,
        path_len=0,
        self_subject="CA-X",
        san_other=ip_san("10.9.9.9"),
        nc_other_excluded=ip_nets("192.0.2.66/32"),
    )
    assert ca_new.cert.is_self_issued

    leaf_ok = issue(
        "h", ca_new.cert, new_key, ca=False, san_other=ip_san("192.0.2.10")
    )
    report = run_ip(leaf_ok, [outer, ca_old, ca_new], r, "192.0.2.10")
    assert report.trusted, failure_text(report)

    leaf_blocked = issue(
        "h", ca_new.cert, new_key, ca=False, san_other=ip_san("192.0.2.66")
    )
    report = run_ip(leaf_blocked, [outer, ca_old, ca_new], r, "192.0.2.66")
    assert not report.trusted
    assert "excluded" in report.failures[0].reason


# --------------------------------------------------------------------------
# Cross-signed alternatives: every candidate chain is judged.
# --------------------------------------------------------------------------


def test_legal_alternative_chain_wins_regardless_of_pool_order():
    r = root()
    r2 = root("Cross Root")
    x_key = p256_key()
    # Direct chain excludes the address; the cross-signed chain permits it.
    x_direct = issue(
        "X",
        r.cert,
        r.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.0.2.0/24"),
        nc_other_excluded=ip_nets("192.0.2.66/32"),
    )
    x_cross = issue(
        "X",
        r2.cert,
        r2.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.0.2.0/24"),
    )
    bridge = issue("Cross Root", r.cert, r.key, subject_key=r2.key, ca=True)
    leaf = issue(
        "h", x_direct.cert, x_key, ca=False, san_other=ip_san("192.0.2.66")
    )

    # Only the constrained chain available: rejected, evidence points at
    # the leaf and names the excluded subtree.
    only = run_ip(leaf, [x_direct], r, "192.0.2.66")
    assert not only.trusted
    assert "excluded" in only.failures[0].reason

    # With the legal alternative present the conclusion is TRUSTED for
    # every input permutation, and the display path is stable.
    expected = None
    for perm in itertools.permutations([x_direct, x_cross, bridge]):
        report = run_ip(leaf, list(perm), r, "192.0.2.66")
        assert report.trusted, failure_text(report)
        seq = tuple(c.sha256 for c in report.chosen_chain.certs)
        expected = expected or seq
        assert seq == expected
    assert x_cross.cert.sha256 in expected


def test_all_candidates_bad_reports_each_first_failure():
    r = root()
    r2 = root("Cross Root")
    x_key = p256_key()
    x_direct = issue(
        "X",
        r.cert,
        r.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        nc_other_permitted=ip_nets("192.0.2.0/25"),
    )
    x_cross = issue(
        "X",
        r2.cert,
        r2.key,
        subject_key=x_key,
        ca=True,
        path_len=0,
        nc_other_excluded=ip_nets("192.0.2.200/32"),
    )
    bridge = issue("Cross Root", r.cert, r.key, subject_key=r2.key, ca=True)
    leaf = issue(
        "h", x_direct.cert, x_key, ca=False, san_other=ip_san("192.0.2.200")
    )
    report = run_ip(leaf, [x_direct, x_cross, bridge], r, "192.0.2.200")
    assert not report.trusted
    assert len(report.failures) == 2
    reasons = " ".join(f.reason for f in report.failures)
    assert "permitted" in reasons and "excluded" in reasons
    assert all(f.failing_cert.sha256 == leaf.cert.sha256 for f in report.failures)


def test_display_path_is_min_digest_sequence():
    r = root()
    r2 = root("Cross Root")
    x_key = p256_key()
    x1 = issue("X", r.cert, r.key, subject_key=x_key, ca=True, path_len=0)
    x2 = issue("X", r2.cert, r2.key, subject_key=x_key, ca=True, path_len=0)
    bridge = issue("Cross Root", r.cert, r.key, subject_key=r2.key, ca=True)
    leaf = issue("h", x1.cert, x_key, ca=False, san_other=ip_san("192.0.2.10"))

    from x509path import build_chains
    from x509path.ipvalidate import validate_ip_chain

    chains, _ = build_chains(leaf.cert, [x1.cert, x2.cert, bridge.cert], r.cert)
    good = [
        tuple(c.sha256 for c in ch.certs)
        for ch in chains
        if validate_ip_chain(ch, VERIFY_AT, ipaddress.ip_address("192.0.2.10"))
        is None
    ]
    assert len(good) >= 2
    report = run_ip(leaf, [x1, x2, bridge], r, "192.0.2.10")
    assert tuple(c.sha256 for c in report.chosen_chain.certs) == min(good)


# --------------------------------------------------------------------------
# Shared profile checks still apply in IP mode.
# --------------------------------------------------------------------------


def test_ip_mode_enforces_shared_profile_checks():
    r = root()
    expired = issue(
        "Expired CA", r.cert, r.key, ca=True, not_after=NOT_BEFORE,
        nc_other_permitted=ip_nets("192.0.2.0/24"),
    )
    leaf = issue(
        "h", expired.cert, expired.key, ca=False, san_other=ip_san("192.0.2.10")
    )
    report = run_ip(leaf, [expired], r, "192.0.2.10")
    assert not report.trusted
    assert "expired" in report.failures[0].reason

    ca = ip_ca("CA", r, path_len=0)
    leaf_no_eku = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_other=ip_san("192.0.2.10"),
        eku_oids=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    report = run_ip(leaf_no_eku, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "serverAuth" in report.failures[0].reason


def test_ip_mode_rejects_bad_san_entries():
    r = root()
    ca = ip_ca("CA", r, path_len=0)
    leaf_uri = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_other=ip_san("192.0.2.10") + [x509.UniformResourceIdentifier("https://h")],
    )
    report = run_ip(leaf_uri, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "disallowed general name" in report.failures[0].reason

    leaf_wild = issue(
        "h",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["*.example.com"],
        san_other=ip_san("192.0.2.10"),
    )
    report = run_ip(leaf_wild, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "wildcard" in report.failures[0].reason


def test_ip_mode_rejects_bad_name_constraints():
    r = root()
    ca = issue(
        "CA",
        r.cert,
        r.key,
        ca=True,
        nc_other_permitted=[x509.UniformResourceIdentifier("https://ca")],
    )
    leaf = issue("h", ca.cert, ca.key, ca=False, san_other=ip_san("192.0.2.10"))
    report = run_ip(leaf, [ca], r, "192.0.2.10")
    assert not report.trusted
    assert "disallowed general name" in report.failures[0].reason


def test_ip_mode_pathlen_still_enforced():
    r = root()
    top = issue("Top", r.cert, r.key, ca=True, path_len=0)
    sub = issue("Sub", top.cert, top.key, ca=True)
    leaf = issue("h", sub.cert, sub.key, ca=False, san_other=ip_san("192.0.2.10"))
    report = run_ip(leaf, [top, sub], r, "192.0.2.10")
    assert not report.trusted
    assert "pathLenConstraint=0" in report.failures[0].reason
    assert report.failures[0].failing_cert.sha256 == top.cert.sha256


# --------------------------------------------------------------------------
# Constraint machinery units.
# --------------------------------------------------------------------------


def test_ip_constraints_merge_and_family_boundaries():
    wide = IpConstraints(permitted=(ipaddress.ip_network("192.0.2.0/24"),))
    narrow = IpConstraints(permitted=(ipaddress.ip_network("192.0.2.0/25"),))
    merged = wide.merge(narrow)
    v4 = ipaddress.ip_address
    assert merged.violation(v4("192.0.2.66")) is None
    assert merged.violation(v4("192.0.2.200")) is not None

    # Disjoint ranges -> empty permitted set, which permits nothing.
    disjoint = IpConstraints(permitted=(ipaddress.ip_network("10.0.0.0/8"),)).merge(
        IpConstraints(permitted=(ipaddress.ip_network("192.168.0.0/16"),))
    )
    assert disjoint.permitted == ()
    assert not disjoint.is_empty()
    assert disjoint.violation(v4("10.0.0.1")) is not None

    # Mixed-family permitted lists intersect per family, never across.
    mixed = IpConstraints(
        permitted=(
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("2001:db8::/32"),
        )
    ).merge(IpConstraints(permitted=(ipaddress.ip_network("2001:db8::/48"),)))
    assert mixed.violation(ipaddress.ip_address("2001:db8::1")) is None
    assert mixed.violation(ipaddress.ip_address("2001:db8:1::1")) is not None
    assert mixed.violation(v4("10.0.0.1")) is not None  # v4 state became empty

    # Exclusions union and win over permissions.
    excl = IpConstraints(
        permitted=(ipaddress.ip_network("192.0.2.0/24"),),
        excluded=(ipaddress.ip_network("192.0.2.66/32"),),
    )
    assert excl.violation(v4("192.0.2.66")) is not None
    assert "excluded" in excl.violation(v4("192.0.2.66"))


def test_mixed_constraints_keep_name_forms_separate():
    state = MixedNameConstraints(
        dns=DnsConstraints(permitted=("good.example.com",)),
        ip=IpConstraints(permitted=(ipaddress.ip_network("192.0.2.0/24"),)),
    )
    assert state.violation("dns", "www.good.example.com") is None
    assert state.violation("dns", "www.other.example.org") is not None
    assert state.violation("ip", ipaddress.ip_address("192.0.2.10")) is None
    assert state.violation("ip", ipaddress.ip_address("198.51.100.1")) is not None
    # A form never seen in permitted subtrees stays unrestricted.
    assert MixedNameConstraints().violation("ip", ipaddress.ip_address("1.2.3.4")) is None
    assert MixedNameConstraints(
        dns=DnsConstraints(permitted=("good.example.com",))
    ).violation("ip", ipaddress.ip_address("1.2.3.4")) is None


# --------------------------------------------------------------------------
# CLI behavior in IP mode.
# --------------------------------------------------------------------------


def _ip_argv(paths, pin, address, extra=()):
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
        "--ip-address",
        address,
    ]
    for p in ints:
        argv += ["--intermediates", p]
    argv += list(extra)
    return argv


def test_cli_ip_json_and_text_agree(tmp_path):
    r, ca, leaf = ip_pki()
    paths = write_tree(tmp_path, r, [ca], leaf)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_run(_ip_argv(paths, r.cert.sha256, "2001:0DB8::10", ["--json"]))
    assert code == 0
    data = json.loads(buf.getvalue())
    assert data["trusted"] is True
    assert data["name_kind"] == "ip"
    assert data["ip_address"] == "2001:db8::10"
    assert "dns_name" not in data

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_run(_ip_argv(paths, r.cert.sha256, "2001:0DB8::10"))
    assert code == 0
    text = buf.getvalue()
    # Text and JSON show the same canonical address and the same path.
    assert "IP       : 2001:db8::10" in text
    for digest in data["display_path_digests"]:
        assert digest in text


def test_cli_ip_untrusted_exit_1_points_at_cert(tmp_path):
    r, ca, leaf = ip_pki()
    leaf66 = issue(
        "excluded.good.example.com",
        ca.cert,
        ca.key,
        ca=False,
        san_dns=["excluded.good.example.com"],
        san_other=ip_san("192.0.2.66"),
    )
    paths = write_tree(tmp_path, r, [ca], leaf66)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_run(_ip_argv(paths, r.cert.sha256, "192.0.2.66"))
    assert code == 1
    out = buf.getvalue()
    assert "NOT TRUSTED" in out
    assert "excluded" in out
    assert leaf66.cert.sha256 in out  # evidence names the failing certificate


@pytest.mark.parametrize(
    "bad", ["2001:db8::10/32", "[::1]", "192.0.2.10:443", "fe80::1%eth0", "junk"]
)
def test_cli_ip_bad_literal_exit_2(tmp_path, bad):
    r, ca, leaf = ip_pki()
    paths = write_tree(tmp_path, r, [ca], leaf)
    assert cli_run(_ip_argv(paths, r.cert.sha256, bad)) == 2


def test_cli_ip_and_dns_flags_are_mutually_exclusive(tmp_path):
    r, ca, leaf = ip_pki()
    paths = write_tree(tmp_path, r, [ca], leaf)
    argv = _ip_argv(paths, r.cert.sha256, "192.0.2.10") + [
        "--dns-name",
        "www.good.example.com",
    ]
    with pytest.raises(SystemExit) as excinfo:
        cli_run(argv)
    assert excinfo.value.code == 2
