"""Restricted offline X.509 path validation.

Only P-256 / ECDSA-SHA256 certificates with ASCII, DNS-only subject names
and name constraints are accepted.  This package deliberately performs path
construction and path validation itself; cryptography is used solely for
parsing and single-certificate signature verification.
"""

from .validate import (
    CandidateFailure,
    DeadEnd,
    PathReport,
    build_chains,
    validate_paths,
)

__all__ = [
    "CandidateFailure",
    "DeadEnd",
    "PathReport",
    "build_chains",
    "validate_paths",
]
