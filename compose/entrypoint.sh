#!/usr/bin/env sh
# Offline verification entry point used by docker compose.
#
# The service runs with `network_mode: none`; this script performs no network
# I/O itself.  Inputs come from environment variables:
#
#   X509PATH_ANCHOR        path to the anchor certificate        (required)
#   X509PATH_ANCHOR_PIN    file containing the SHA-256(DER) hex  (required,
#                          unless --anchor-pin is passed through X509PATH_ARGS)
#   X509PATH_SERVER        path to the server certificate        (required)
#   X509PATH_INTERMEDIATES whitespace/colon separated intermediate files
#   X509PATH_AT            ISO-8601 verification moment w/ tz    (required)
#   X509PATH_DNS_NAME      exact ASCII DNS name            (required unless
#                          X509PATH_IP_ADDRESS is set)
#   X509PATH_IP_ADDRESS    exact unscoped IPv4/IPv6 literal; when set it
#                          takes precedence over X509PATH_DNS_NAME
#   X509PATH_JSON          set to 1 for JSON output
#   X509PATH_EXTRA_ARGS    any additional arguments
set -eu

: "${X509PATH_ANCHOR:?X509PATH_ANCHOR is required}"
: "${X509PATH_ANCHOR_PIN:?X509PATH_ANCHOR_PIN (pin file) is required}"
: "${X509PATH_SERVER:?X509PATH_SERVER is required}"
: "${X509PATH_AT:?X509PATH_AT verification moment is required}"

set -- \
  --anchor "$X509PATH_ANCHOR" \
  --anchor-pin-file "$X509PATH_ANCHOR_PIN" \
  --server "$X509PATH_SERVER" \
  --at "$X509PATH_AT"

if [ -n "${X509PATH_IP_ADDRESS:-}" ]; then
  set -- "$@" --ip-address "$X509PATH_IP_ADDRESS"
elif [ -n "${X509PATH_DNS_NAME:-}" ]; then
  set -- "$@" --dns-name "$X509PATH_DNS_NAME"
else
  echo "error: X509PATH_IP_ADDRESS or X509PATH_DNS_NAME is required" >&2
  exit 2
fi

if [ -n "${X509PATH_INTERMEDIATES:-}" ]; then
  # Accept colon- or whitespace-separated lists.
  for f in $(printf '%s\n' "$X509PATH_INTERMEDIATES" | tr ':' ' '); do
    set -- "$@" --intermediates "$f"
  done
fi

if [ "${X509PATH_JSON:-0}" = "1" ]; then
  set -- "$@" --json
fi

if [ -n "${X509PATH_EXTRA_ARGS:-}" ]; then
  # shellcheck disable=SC2086
  set -- "$@" $X509PATH_EXTRA_ARGS
fi

exec python -m x509path.cli "$@"
