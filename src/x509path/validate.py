"""Candidate chain construction and RFC 5280 path validation.

Chains are constructed from actual signatures ("建立实际签名成立的候选链"),
cycles are prevented by a per-path digest set, and every complete path that
reaches the pinned anchor is validated independently.  Same-DN / different-key
CAs therefore cannot shadow each other.
"""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .certwrap import Cert, directly_issued_by
from .dnsnames import DnsConstraints
from .rules import (
    basic_constraints_path_len,
    check_basic_constraints,
    check_common_profile,
    check_eku_server_auth,
    check_key_usage,
    check_validity,
    extract_dns_names,
    extract_name_constraints,
)

MAX_INTERMEDIATES = 8
# Chain length is bounded by MAX_INTERMEDIATES; this only guards pathological
# enumeration of a malformed pool.
_MAX_CANDIDATES = 20000


@dataclass(frozen=True)
class DeadEnd:
    """A traversal that could not reach the anchor, identified by the tip."""

    tip: Cert
    reason: str

    def as_dict(self) -> dict:
        return {
            "certificate_subject": _dn(self.tip.subject),
            "certificate_digest": self.tip.sha256,
            "reason": self.reason,
        }


@dataclass
class Chain:
    """A chain ordered anchor -> leaf (anchor first, leaf last)."""

    certs: List[Cert]
    dead_ends: List[DeadEnd] = field(default_factory=list)

    @property
    def anchor(self) -> Cert:
        return self.certs[0]

    @property
    def leaf(self) -> Cert:
        return self.certs[-1]


def _dn(name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return "<unprintable name>"


def build_chains(
    leaf: Cert,
    intermediates: List[Cert],
    anchor: Cert,
    max_intermediates: int = MAX_INTERMEDIATES,
) -> Tuple[List[Chain], List[DeadEnd]]:
    """Enumerate every signature-valid simple path from leaf to anchor.

    * A same-DN pool entry with a different key simply fails edge
      verification and never shadows the matching-key issuer.
    * Cycles (including self-signed lookalikes and self-issued key-change
      loops) are blocked with a per-trail digest set.
    * The only accepted sink is the pinned anchor reached via a real
      signature.  A self-signed cert in the pool can never be the sink.
    """
    # De-duplicate the pool by DER digest; a pool cert identical to the
    # anchor is removed (the anchor itself is the only valid sink).
    pool: Dict[str, Cert] = {}
    for c in intermediates:
        if c.sha256 != anchor.sha256:
            pool[c.sha256] = c

    by_subject: Dict[str, List[Cert]] = defaultdict(list)
    for c in pool.values():
        by_subject[c.subject].append(c)

    chains: List[Chain] = []
    dead_tips: Dict[str, DeadEnd] = {}
    truncated = False

    def record_dead(tip: Cert, reason: str) -> None:
        dead_tips.setdefault(tip.sha256, DeadEnd(tip=tip, reason=reason))

    def dfs(current: Cert, trail_leaf_first: List[Cert], used: Set[str]) -> None:
        nonlocal truncated
        if len(chains) >= _MAX_CANDIDATES:
            truncated = True
            return

        # Sink: pinned anchor actually signs the current cert.
        if directly_issued_by(current, anchor):
            chains.append(Chain(certs=[anchor] + list(reversed(trail_leaf_first))))
            return

        candidates = by_subject.get(current.issuer, [])
        if not candidates:
            record_dead(current, "no certificate with matching issuer DN in input")
            return

        extended = False
        anchor_match = False
        for issuer in candidates:
            if issuer.sha256 in used:
                # Would close a certificate ring: refuse this edge.
                record_dead(current, "issuer edge would create a certificate ring")
                continue
            if not directly_issued_by(current, issuer):
                # Same-DN / wrong-key entry (or a malformed edge): never a
                # substitute for the genuinely signing issuer.
                continue
            extended = True
            trail_leaf_first.append(issuer)
            used.add(issuer.sha256)
            if len(trail_leaf_first) - 1 > max_intermediates:
                record_dead(
                    issuer,
                    f"chain requires more than {max_intermediates} intermediates",
                )
            else:
                dfs(issuer, trail_leaf_first, used)
            used.discard(issuer.sha256)
            trail_leaf_first.pop()
            if len(chains) >= _MAX_CANDIDATES:
                truncated = True
                return

        # A same-DN cert that does not cryptographically sign the current
        # certificate must not be silently accepted as issuer; report it so
        # the failure is diagnosable.
        if not extended:
            if current.issuer == anchor.subject:
                record_dead(
                    current,
                    "anchor shares the issuer DN but does not sign this certificate",
                )
            else:
                record_dead(
                    current,
                    "issuer-DN candidates exist but none verifiably sign this "
                    "certificate (same name, different key, or bad signature)",
                )

    dfs(leaf, [leaf], {leaf.sha256})
    if truncated:
        record_dead(
            leaf,
            f"candidate enumeration truncated after {_MAX_CANDIDATES} paths",
        )
    return chains, list(dead_tips.values())


@dataclass(frozen=True)
class CandidateFailure:
    """The first certificate at which a candidate chain fails, and why."""

    chain: Chain
    failing_cert: Cert
    layer: int  # 0 = anchor's direct subordinate, increases toward the leaf
    reason: str

    def as_dict(self) -> dict:
        return {
            "failing_certificate_subject": _dn(self.failing_cert.subject),
            "failing_certificate_digest": self.failing_cert.sha256,
            "layer_from_anchor": self.layer,
            "reason": self.reason,
            "chain_digests": [c.sha256 for c in self.chain.certs],
        }


@dataclass
class PathReport:
    trusted: bool
    dns_name: Optional[str]
    moment: _dt.datetime
    chosen_chain: Optional[Chain] = None
    failures: List[CandidateFailure] = field(default_factory=list)
    dead_ends: List[DeadEnd] = field(default_factory=list)
    leaf_san_error: Optional[str] = None

    # Plain class attribute (not a dataclass field): IpPathReport overrides
    # it so text output can label the requested name correctly.
    name_kind = "dns"

    def as_dict(self) -> dict:
        out = {
            "trusted": self.trusted,
            "dns_name": self.dns_name,
            "verification_time": self.moment.isoformat(),
        }
        if self.chosen_chain is not None:
            out["display_path"] = [
                {
                    "position": i,
                    "subject": _dn(c.subject),
                    "issuer": _dn(c.issuer),
                    "sha256_der": c.sha256,
                }
                for i, c in enumerate(self.chosen_chain.certs)
            ]
            out["display_path_digests"] = [c.sha256 for c in self.chosen_chain.certs]
        if self.failures:
            out["candidate_failures"] = [f.as_dict() for f in self.failures]
        if self.dead_ends:
            out["uncompleted_trails"] = [d.as_dict() for d in self.dead_ends]
        if self.leaf_san_error:
            out["leaf_san_error"] = self.leaf_san_error
        return out


def validate_chain(
    chain: Chain, moment: _dt.datetime, dns_name: str
) -> CandidateFailure:
    """Validate one complete chain from the anchor outward.

    The anchor's own signature and validity are deliberately not checked.
    Returns the first failure encountered, or ``None`` when valid.
    """
    certs = chain.certs  # anchor first, leaf last
    leaf = chain.leaf

    # Leaf SAN/profile sanity first: DNS-only SAN and the exact name.
    san_names, san_err = extract_dns_names(leaf)
    if san_err is not None:
        return CandidateFailure(chain, leaf, len(certs) - 1, san_err)
    if dns_name.lower() not in san_names:
        return CandidateFailure(
            chain,
            leaf,
            len(certs) - 1,
            f"exact DNS name {dns_name!r} not present in leaf SAN "
            f"{list(san_names)!r} (wildcards not supported)",
        )

    # Top-down checks beginning at the anchor's direct subordinate.
    accumulated = DnsConstraints()
    for layer in range(1, len(certs)):
        cert = certs[layer]
        is_leaf = layer == len(certs) - 1

        res = check_common_profile(cert)
        if not res.ok:
            return CandidateFailure(chain, cert, layer, res.reason)
        res = check_validity(cert, moment)
        if not res.ok:
            return CandidateFailure(chain, cert, layer, res.reason)
        res = check_basic_constraints(cert, is_leaf)
        if not res.ok:
            return CandidateFailure(chain, cert, layer, res.reason)
        res = check_key_usage(cert, is_leaf)
        if not res.ok:
            return CandidateFailure(chain, cert, layer, res.reason)
        res = check_eku_server_auth(cert, is_leaf)
        if not res.ok:
            return CandidateFailure(chain, cert, layer, res.reason)

        if not is_leaf:
            # Accumulate this CA's constraints before applying them:
            # RFC 5280 6.1.4(h)(2) applies the state to all subordinate
            # certificates, not to the CA bearing the extension.
            nc, nc_err = extract_name_constraints(cert)
            if nc_err is not None:
                return CandidateFailure(chain, cert, layer, nc_err)
            if nc is not None:
                accumulated = accumulated.merge(nc)

    # pathLenConstraint: counts non-self-issued intermediates BELOW each CA.
    # RFC 5280 4.2.1.9: self-issued certificates are not counted.
    if len(certs) > 2:
        for layer in range(1, len(certs) - 1):
            ca = certs[layer]
            bound = basic_constraints_path_len(ca)
            if bound is None:
                continue
            below = 0
            for k in range(layer + 1, len(certs) - 1):
                if not certs[k].is_self_issued:
                    below += 1
            if below > bound:
                return CandidateFailure(
                    chain,
                    ca,
                    layer,
                    f"pathLenConstraint={bound} violated: "
                    f"{below} non-self-issued intermediate CA(s) follow",
                )

    # Apply accumulated DNS constraints to every leaf SAN name.
    if not accumulated.is_empty():
        for name in san_names:
            violation = accumulated.violation(name)
            if violation is not None:
                return CandidateFailure(chain, leaf, len(certs) - 1, violation)

    return None


def validate_paths(
    leaf: Cert,
    intermediates: List[Cert],
    anchor: Cert,
    moment: _dt.datetime,
    dns_name: str,
    max_intermediates: int = MAX_INTERMEDIATES,
) -> PathReport:
    chains, dead_ends = build_chains(leaf, intermediates, anchor, max_intermediates)

    failures: List[CandidateFailure] = []
    valid: List[Chain] = []
    for chain in chains:
        failure = validate_chain(chain, moment, dns_name)
        if failure is None:
            valid.append(chain)
        else:
            failures.append(failure)

    chosen: Optional[Chain] = None
    if valid:
        # Deterministic, content-defined unique display path: the DER digest
        # sequence anchor -> leaf must be lexicographically smallest.
        chosen = min(valid, key=lambda ch: tuple(c.sha256 for c in ch.certs))

    return PathReport(
        trusted=chosen is not None,
        dns_name=dns_name,
        moment=moment,
        chosen_chain=chosen,
        failures=failures,
        dead_ends=dead_ends,
    )
