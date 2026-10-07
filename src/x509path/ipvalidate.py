"""IP candidate validation through the certificate signature graph."""

from .generalnames import parse_ip, san_names, constraints, NamePolicy
from .validate import build_chains, CandidateFailure, PathReport, MAX_INTERMEDIATES
from .rules import (
    check_common_profile,
    check_validity,
    check_basic_constraints,
    check_key_usage,
    check_eku_server_auth,
    basic_constraints_path_len,
)


class IpPathReport(PathReport):
    def as_dict(self):
        doc = super().as_dict()
        doc["ip_address"] = doc.pop("dns_name")
        doc["name_kind"] = "ip"
        return doc


def validate_ip_chain(chain, moment, address):
    leaf = chain.leaf
    policy = NamePolicy()
    try:
        names = san_names(leaf, True)
    except ValueError as error:
        return CandidateFailure(chain, leaf, len(chain.certs) - 1, str(error))
    if not any(value == address for kind, value in names):
        return CandidateFailure(
            chain, leaf, len(chain.certs) - 1, "requested IP address is absent from SAN"
        )
    for i, cert in enumerate(chain.certs[1:], 1):
        last = i == len(chain.certs) - 1
        results = [
            check_common_profile(cert),
            check_validity(cert, moment),
            check_basic_constraints(cert, last),
            check_key_usage(cert, last),
            check_eku_server_auth(cert, last),
        ]
        for result in results:
            if not result.ok:
                return CandidateFailure(chain, cert, i, result.reason)
        if not last:
            policy.add(constraints(cert))
    failure = policy.violation(names)
    if failure:
        return CandidateFailure(chain, leaf, len(chain.certs) - 1, failure)
    for i, cert in enumerate(chain.certs[1:-1], 1):
        limit = basic_constraints_path_len(cert)
        if (
            limit is not None
            and sum(not c.is_self_issued for c in chain.certs[i + 1 : -1]) > limit
        ):
            return CandidateFailure(chain, cert, i, "pathLenConstraint exceeded")
    return None


def validate_ip_paths(
    leaf, intermediates, anchor, moment, ip_address, max_intermediates=MAX_INTERMEDIATES
):
    requested = parse_ip(ip_address)
    chains, dead = build_chains(leaf, intermediates, anchor, max_intermediates)
    selected = None
    failures = []
    if chains:
        candidate = chains[0]
        failure = validate_ip_chain(candidate, moment, requested)
        if failure is None:
            selected = candidate
        else:
            failures.append(failure)
    return IpPathReport(
        trusted=selected is not None,
        dns_name=requested,
        moment=moment,
        chosen_chain=selected,
        failures=failures,
        dead_ends=dead,
    )
