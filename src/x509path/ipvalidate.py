"""IP-address path validation through the certificate signature graph.

Mirrors :func:`x509path.validate.validate_paths` for the mixed DNS/IP
profile: every signature-valid candidate chain is validated independently,
the trust conclusion is deterministic, and the display path is the valid
chain with the lexicographically smallest DER-digest sequence — never the
first chain that happened to be enumerated.
"""

from __future__ import annotations

import datetime as _dt
from typing import List, Optional

from .certwrap import Cert
from .generalnames import (
    MixedNameConstraints,
    extract_mixed_name_constraints,
    extract_mixed_san,
    parse_ip_literal,
)
from .rules import (
    basic_constraints_path_len,
    check_basic_constraints,
    check_common_profile,
    check_eku_server_auth,
    check_key_usage,
    check_validity,
)
from .validate import (
    MAX_INTERMEDIATES,
    CandidateFailure,
    Chain,
    PathReport,
    build_chains,
)


class IpPathReport(PathReport):
    """Path report for IP verification; JSON carries the canonical address."""

    name_kind = "ip"

    def as_dict(self) -> dict:
        doc = super().as_dict()
        doc["ip_address"] = doc.pop("dns_name")
        doc["name_kind"] = "ip"
        return doc


def validate_ip_chain(
    chain: Chain, moment: _dt.datetime, address
) -> Optional[CandidateFailure]:
    """Validate one complete chain for an IP request, anchor outward.

    Same check order as DNS mode: leaf SAN profile and requested-address
    presence first, then per-layer profile/validity/basicConstraints/
    keyUsage/EKU, then pathLenConstraint, and finally the accumulated
    name constraints applied to every subordinate SAN name.  Returns the
    first failure encountered, or ``None`` when the chain is valid.
    """
    certs = chain.certs  # anchor first, leaf last
    leaf = chain.leaf

    # Leaf SAN/profile sanity first: mixed DNS/IP SAN and the exact address.
    # The GeneralName type decides identity: a dNSName — even a numeric one
    # — never satisfies an IP request.
    san_names, san_err = extract_mixed_san(leaf, required=True)
    if san_err is not None:
        return CandidateFailure(chain, leaf, len(certs) - 1, san_err)
    if not any(kind == "ip" and value == address for kind, value in san_names):
        return CandidateFailure(
            chain,
            leaf,
            len(certs) - 1,
            f"exact IP address {address} not present in leaf SAN "
            f"{[str(v) for _, v in san_names]!r} "
            "(dNSName entries never satisfy an IP request)",
        )

    # Top-down checks beginning at the anchor's direct subordinate.
    accumulated = MixedNameConstraints()
    # SAN-vs-constraints checks are deferred until after pathLen processing
    # (same reporting order as DNS mode); each entry keeps the state that
    # was accumulated above the certificate, never its own constraints.
    deferred = []
    for layer in range(1, len(certs)):
        cert = certs[layer]
        is_leaf = layer == len(certs) - 1

        for res in (
            check_common_profile(cert),
            check_validity(cert, moment),
            check_basic_constraints(cert, is_leaf),
            check_key_usage(cert, is_leaf),
            check_eku_server_auth(cert, is_leaf),
        ):
            if not res.ok:
                return CandidateFailure(chain, cert, layer, res.reason)

        if is_leaf:
            names = san_names
        else:
            names, san_err = extract_mixed_san(cert, required=False)
            if san_err is not None:
                return CandidateFailure(chain, cert, layer, san_err)
        # RFC 5280 6.1.4(h)/(i): a self-issued certificate that is not the
        # final one is exempt from the name constraints accumulated above
        # it — but its own name constraints (merged below) still bind every
        # descendant, so a key-change node and its successors stay
        # consistent.
        if names and not (cert.is_self_issued and not is_leaf):
            deferred.append((layer, cert, names, accumulated))

        if not is_leaf:
            # Accumulate this CA's constraints before applying them:
            # the state constrains subordinate certificates, never the CA
            # bearing the extension.
            nc, nc_err = extract_mixed_name_constraints(cert)
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

    # Apply the accumulated constraints to every subordinate SAN name, from
    # the anchor's subordinate outward; the first violation rejects.
    for layer, cert, names, state in deferred:
        if state.is_empty():
            continue
        for kind, value in names:
            violation = state.violation(kind, value)
            if violation is not None:
                return CandidateFailure(chain, cert, layer, violation)

    return None


def validate_ip_paths(
    leaf: Cert,
    intermediates: List[Cert],
    anchor: Cert,
    moment: _dt.datetime,
    ip_address: str,
    max_intermediates: int = MAX_INTERMEDIATES,
) -> IpPathReport:
    """Validate every candidate chain for ``ip_address`` and report.

    The requested literal is parsed once into its canonical form; every
    complete candidate chain is judged on its own, and when at least one
    is valid the display path is the one whose anchor-to-leaf DER digest
    sequence is lexicographically smallest — so the conclusion and the
    reported path never depend on the order of the input intermediates.
    """
    requested = parse_ip_literal(ip_address)
    chains, dead_ends = build_chains(leaf, intermediates, anchor, max_intermediates)

    failures: List[CandidateFailure] = []
    valid: List[Chain] = []
    for chain in chains:
        failure = validate_ip_chain(chain, moment, requested)
        if failure is None:
            valid.append(chain)
        else:
            failures.append(failure)

    chosen: Optional[Chain] = None
    if valid:
        chosen = min(valid, key=lambda ch: tuple(c.sha256 for c in ch.certs))

    return IpPathReport(
        trusted=chosen is not None,
        dns_name=str(requested),  # canonical display form, shown as ip_address
        moment=moment,
        chosen_chain=chosen,
        failures=failures,
        dead_ends=dead_ends,
    )
