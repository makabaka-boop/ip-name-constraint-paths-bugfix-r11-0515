"""Command-line entry point for offline, restricted path validation."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from typing import List, Optional

from .certwrap import Cert, load_cert_file
from .dnsnames import validate_strict_dns
from .ipvalidate import validate_ip_paths
from .validate import MAX_INTERMEDIATES, PathReport, validate_paths


def _parse_moment(value: str) -> _dt.datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = _dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"bad verification time {value!r}: {exc}") from exc
    if moment.tzinfo is None:
        raise ValueError(
            f"verification time {value!r} must carry an explicit timezone "
            "(e.g. 2026-06-15T12:00:00Z)"
        )
    return moment.astimezone(_dt.timezone.utc)


def _load_one(path: str, what: str) -> Cert:
    certs = load_cert_file(path)
    if len(certs) != 1:
        raise ValueError(
            f"{what} file {path} must contain exactly one certificate, "
            f"found {len(certs)}"
        )
    return certs[0]


def _load_intermediates(paths: List[str]) -> List[Cert]:
    certs: List[Cert] = []
    seen = set()
    for path in paths:
        for cert in load_cert_file(path):
            if cert.sha256 not in seen:
                seen.add(cert.sha256)
                certs.append(cert)
    return certs


def _resolve_pin(args: argparse.Namespace) -> str:
    raw: Optional[str] = args.anchor_pin or os.environ.get("X509PATH_ANCHOR_PIN")
    if args.anchor_pin_file:
        with open(args.anchor_pin_file, "r", encoding="ascii") as fh:
            raw = fh.read().strip()
    if not raw:
        raise ValueError(
            "no anchor pin given; use --anchor-pin, --anchor-pin-file or "
            "X509PATH_ANCHOR_PIN (hex SHA-256 of the anchor DER)"
        )
    pin = raw.strip().split()[0].lower().replace(":", "")
    if len(pin) != 64:
        raise ValueError(
            f"anchor pin must be a 32-byte hex digest (64 chars), got {len(pin)}"
        )
    int(pin, 16)  # raises ValueError on non-hex
    return pin


def _dn(name) -> str:
    return name.rfc4514_string()


def _print_human(report: PathReport, anchor: Cert, stream) -> None:
    # DNS and IP output show the same canonical name the JSON report uses.
    label = "IP" if getattr(report, "name_kind", "dns") == "ip" else "Name"
    if report.trusted:
        stream.write("RESULT: TRUSTED\n")
        stream.write(f"{label:<9}: {report.dns_name}\n")
        stream.write(f"moment   : {report.moment.isoformat()}\n")
        stream.write("display path (unique, by DER digest order):\n")
        for i, cert in enumerate(report.chosen_chain.certs):
            role = (
                "ANCHOR"
                if i == 0
                else "LEAF" if i == len(report.chosen_chain.certs) - 1 else "CA  "
            )
            stream.write(
                f"  [{i}] {role} sha256={cert.sha256}\n"
                f"        subject={_dn(cert.subject)}\n"
                f"        issuer ={_dn(cert.issuer)}\n"
            )
        return

    stream.write("RESULT: NOT TRUSTED\n")
    stream.write(f"{label:<9}: {report.dns_name}\n")
    if report.failures:
        stream.write(
            f"{len(report.failures)} complete candidate chain(s) reached the "
            "anchor; first failure of each:\n"
        )
        for i, failure in enumerate(report.failures, 1):
            stream.write(
                f"  candidate {i}: layer {failure.layer} "
                f"(subject={_dn(failure.failing_cert.subject)}, "
                f"sha256={failure.failing_cert.sha256})\n"
                f"      -> {failure.reason}\n"
            )
    else:
        stream.write("no signature-valid chain reaches the pinned anchor.\n")
    if report.dead_ends:
        stream.write("uncompleted trails (by first stuck certificate):\n")
        for dead in report.dead_ends:
            stream.write(
                f"  - subject={_dn(dead.tip.subject)} "
                f"sha256={dead.tip.sha256}\n      -> {dead.reason}\n"
            )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="x509path",
        description=(
            "Offline restricted X.509 path validation. Pins one trust anchor "
            "by SHA-256 of its DER, accepts one server cert and up to "
            f"{MAX_INTERMEDIATES} unordered intermediates. P-256 / "
            "ECDSA-SHA256, ASCII DNS-only names/SAN/name constraints. "
            "No revocation, policies, or wildcards. No full-path validator "
            "is used for the decision."
        ),
    )
    p.add_argument("--anchor", required=True, help="trust anchor certificate (PEM/DER)")
    p.add_argument(
        "--anchor-pin",
        help="required SHA-256 hex of the anchor DER (or X509PATH_ANCHOR_PIN)",
    )
    p.add_argument(
        "--anchor-pin-file",
        help="file containing the anchor SHA-256 hex digest",
    )
    p.add_argument("--server", required=True, help="server/end-entity certificate")
    p.add_argument(
        "--intermediates",
        action="append",
        default=[],
        help="intermediate certificate file (PEM may concatenate several); "
        "repeatable, at most 8 distinct certificates total",
    )
    p.add_argument(
        "--at",
        required=True,
        help="verification moment, ISO-8601 with timezone (e.g. 2026-06-15T12:00:00Z)",
    )
    names = p.add_mutually_exclusive_group(required=True)
    names.add_argument("--ip-address", help="exact unscoped IPv4 or IPv6 SAN address")
    names.add_argument(
        "--dns-name",
        help="exact ASCII DNS name that must appear in the leaf SAN",
    )
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return p


def run(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        pin = _resolve_pin(args)
        anchor = _load_one(args.anchor, "anchor")
        if anchor.sha256 != pin:
            raise ValueError(
                "anchor pin mismatch: provided certificate SHA-256(DER)="
                f"{anchor.sha256} does not equal pinned digest {pin}"
            )
        leaf = _load_one(args.server, "server")
        intermediates = _load_intermediates(args.intermediates)
        if len(intermediates) > MAX_INTERMEDIATES:
            raise ValueError(
                f"at most {MAX_INTERMEDIATES} distinct intermediate certificates "
                f"are accepted, got {len(intermediates)}"
            )
        moment = _parse_moment(args.at)
        if args.ip_address is not None:
            report = validate_ip_paths(
                leaf, intermediates, anchor, moment, args.ip_address
            )
        else:
            dns_name = validate_strict_dns(args.dns_name)
            report = validate_paths(
                leaf=leaf,
                intermediates=intermediates,
                anchor=anchor,
                moment=moment,
                dns_name=dns_name,
            )
    except (ValueError, OSError) as exc:
        msg = f"error: {exc}"
        if getattr(args, "json", False):
            print(json.dumps({"error": msg}, indent=2))
        else:
            print(msg, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    else:
        _print_human(report, anchor, sys.stdout)
    return 0 if report.trusted else 1


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
