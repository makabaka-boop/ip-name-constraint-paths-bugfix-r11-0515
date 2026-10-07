"""Unit tests for DNS parsing and RFC 5280 name-constraint accumulation."""

import pytest

from x509path.dnsnames import (
    DnsConstraints,
    constraint_matches,
    in_domain,
    validate_strict_dns,
)


@pytest.mark.parametrize(
    "value",
    ["example.com", "a.b.c.example.org", "WWW.Example.COM", "x-y.io", "1.io"],
)
def test_strict_dns_accepts(value):
    validate_strict_dns(value)


@pytest.mark.parametrize(
    "value",
    [
        "*.example.com",
        ".example.com",
        "example.com.",
        "exa mple.com",
        "example..com",
        "-bad.com",
        "bad-.com",
        "www.éxample.com",
        "",
        "a" * 64 + ".com",
    ],
)
def test_strict_dns_rejects(value):
    with pytest.raises(ValueError):
        validate_strict_dns(value)


def test_in_domain():
    assert in_domain("a.b.example.com", "example.com")
    assert in_domain("example.com", "example.com")
    assert not in_domain("notexample.com", "example.com")
    assert not in_domain("a.com", "example.com")
    assert not in_domain("com", "example.com")


def test_constraint_matching_plain_and_leading_dot():
    assert constraint_matches("example.com", "example.com")
    assert constraint_matches("example.com", "host.example.com")
    assert not constraint_matches(".example.com", "example.com")
    assert constraint_matches(".example.com", "host.example.com")
    assert constraint_matches(".example.com", "x.host.example.com")
    assert not constraint_matches("example.com", "notexample.com")
    assert constraint_matches("", "anything.example.org")


def test_merge_intersects_permitted_and_unions_excluded():
    a = DnsConstraints(permitted=("example.com",))
    b = DnsConstraints(permitted=(".example.com",))
    m = a.merge(b)
    assert m.allows("host.example.com")
    assert not m.allows("example.com")  # leading dot drops the apex

    wide = DnsConstraints(permitted=("example.com",))
    narrow = DnsConstraints(permitted=("www.example.com",))
    m2 = wide.merge(narrow)
    assert m2.allows("www.example.com")
    assert not m2.allows("api.example.com")

    m3 = DnsConstraints(excluded=("a.example.com",)).merge(
        DnsConstraints(excluded=("b.example.com",))
    )
    assert not m3.allows("a.example.com")
    assert not m3.allows("x.b.example.com")
    assert m3.allows("c.example.com")


def test_merge_exclusion_cannot_be_readmitted():
    m = DnsConstraints(excluded=("corp.example.com",)).merge(
        DnsConstraints(permitted=("corp.example.com",))
    )
    # The excluded cone is empty even though a deeper CA permits it:
    # the apex and every sub-domain remain blocked.
    assert not m.allows("x.corp.example.com")
    assert not m.allows("host.corp.example.com")
    assert not m.allows("corp.example.com")
    # Inner permitted cone narrows the previously-unrestricted state.
    assert not m.allows("other.example.com")
