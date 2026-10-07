# x509path — restricted offline X.509 path validation

A small command-line tool that answers exactly one question offline:

> Given **one pinned trust anchor** (identified by SHA-256 of its DER),
> **one server certificate**, **at most eight unordered intermediate
> certificates**, a **verification moment**, and an **exact DNS name** —
> does at least one standards-conformant certificate path exist?

It deliberately implements path construction and path validation itself.
`cryptography` is used only to parse certificates and to verify a **single**
ECDSA signature on one edge; no full-path / "verify" API is ever used to make
the trust decision.

## Why it exists

Stopping at the *first* certificate whose subject DN matches an issuer DN is
wrong when two CAs legitimately share a name but use different keys, which is
exactly the configuration created by cross-certification and key rollover:

* a same-DN / wrong-key entry encountered first would make a validator reject
  a perfectly legal chain;
* picking a same-DN cross-certificate that carries different name constraints
  could let a name through that the real chain forbids.

`x509path` therefore enumerates **every** path whose edges hold
cryptographically (name binding **and** signature verification), prevents
cycles, and validates each complete path independently.

## Accepted certificate profile

Every certificate in the path **except the anchor** must satisfy:

| aspect | rule |
|---|---|
| version | X.509 v3 |
| public key | P-256 (`secp256r1`) |
| signature | `ecdsa-with-SHA256` on every edge |
| names | ASCII only |
| leaf SAN | present, **only** `dNSName` entries (no IP, email, URI, …), strict LDH syntax |
| name constraints | **only** `dNSName` permitted/excluded subtrees, ASCII |
| DNS lookup name | exact match (case-insensitive); **no wildcards** |
| leaf `basicConstraints` | `cA=false` (or absent) |
| CA `basicConstraints` | present, `cA=true`; `pathLenConstraint` honored |
| `keyUsage` | present; leaf asserts `digitalSignature`, CAs assert `keyCertSign` |
| `extKeyUsage` | leaf must contain `serverAuth` (no `anyEKU` loophole); a CA EKU, if present, must permit `serverAuth` |
| other critical extensions | **rejected** (policies, policy mappings/constraints, `inhibitAnyPolicy`, CRL distribution points, unknown/private OIDs, …) |

Explicitly **not** performed: revocation (CRL/OCSP), certificate policies /
policy mapping / `anyPolicy`, wildcard matching, AIA fetching — and **no
network I/O at all**.

The **anchor's own signature and validity period are not checked**; it is
trusted solely because its DER SHA-256 equals the pinned digest.

## Validation semantics (RFC 5280)

Starting at the anchor's **direct subordinate** and walking outward:

1. profile checks (version, P-256, ECDSA-SHA256, critical-extension allowlist);
2. validity window against the supplied moment;
3. `basicConstraints` (CA vs leaf);
4. `keyUsage` purpose bits;
5. `extKeyUsage` `serverAuth` purpose at every layer;
6. accumulation of name constraints — permitted subtrees are
   **intersected**, excluded subtrees are **unioned**; an outer exclusion can
   never be re-admitted by an inner permit; the empty permitted set means
   "any DNS";
7. `pathLenConstraint` counting only **non-self-issued** intermediates below
   the bound CA (RFC 5280 4.2.1.9);
8. the accumulated permitted/excluded DNS ranges are applied to **every**
   `dNSName` in the leaf SAN, and the requested name must be present exactly.

DNS constraints follow RFC 5280 4.2.1.10: `example.com` matches the host and
all sub-domains; `.example.com` matches sub-domains **only**, never the apex.

**Self-issued key-change nodes** (subject DN == issuer DN, but signed by a
different key) are threaded through normally, are exempt from the
`pathLenConstraint` count, and are **not** treated as self-signed roots. A
self-signed lookalike in the intermediate pool can never terminate a chain —
only the pinned anchor can.

## Result determinism

* If at least one valid path exists, the reported **display path** is the
  valid path whose tuple of SHA-256(DER) digests from anchor to leaf is
  lexicographically smallest. It is unique and independent of the order of
  input files.
* If none exists, the output lists **every complete candidate chain's first
  failing certificate and violated constraint**, plus the dead-end
  certificates that could not be extended to the anchor (missing issuer,
  same-DN wrong-key edge, or an edge that would close a certificate ring).

## CLI

```
x509path \
  --anchor anchor.pem \
  --anchor-pin 98076f885caf3c08…a91cf4 \
  --server server.pem \
  --intermediates a.pem --intermediates b.pem … \
  --at 2026-06-15T12:00:00Z \
  --dns-name www.good.example.com \
  [--json]
```

`--dns-name` and `--ip-address` are mutually exclusive.  IP mode takes an
exact, unscoped IPv4/IPv6 literal (no port, brackets, zone id or subnet),
canonicalizes it, and matches it against iPAddress SAN entries by address
content — a dNSName never satisfies an IP request, and IPv4/IPv6 are never
converted into each other.  SANs and name constraints may mix dNSName and
iPAddress; constraint state is tracked per name form (permitted subtrees of
one form never restrict the other), permitted ranges intersect across CAs,
exclusions union and always win, and every subordinate SAN name is checked.
JSON output marks `"name_kind": "ip"` and the canonical `"ip_address"`;
text and JSON always show the same canonical name and the same display path.

The pin may also be supplied via `--anchor-pin-file` or
`X509PATH_ANCHOR_PIN`. Up to 8 distinct intermediates are accepted; a PEM
file may concatenate several certificates. PEM and DER inputs are accepted.

Exit codes: `0` trusted, `1` reached a decision of not trusted (details
printed), `2` usage / input / pin error.

## Offline entry point with Docker Compose

The Compose service installs dependencies at build time and then runs with
`network_mode: none` and a read-only root filesystem:

```sh
python3 scripts/generate_sample_pki.py
docker compose run --rm \
  -e X509PATH_AT=2026-06-15T12:00:00Z \
  -e X509PATH_DNS_NAME=www.good.example.com \
  validator

# a name outside the issuing CA's permitted subtree
docker compose run --rm \
  -e X509PATH_AT=2026-06-15T12:00:00Z \
  -e X509PATH_DNS_NAME=www.good.example.org \
  -e X509PATH_SERVER=/app/examples/pki/extra/server-org.pem \
  -e X509PATH_JSON=1 \
  validator; echo "exit=$?"

# IP-address verification of the mixed-SAN sample leaf
docker compose run --rm \
  -e X509PATH_SERVER=/app/examples/pki/server-ip.pem \
  -e X509PATH_INTERMEDIATES=/app/examples/pki/intermediates/issuing-ip.pem \
  -e X509PATH_IP_ADDRESS=2001:db8::10 \
  validator
```

Environment variables consumed by `compose/entrypoint.sh`:
`X509PATH_ANCHOR`, `X509PATH_ANCHOR_PIN` (path to the pin **file**),
`X509PATH_SERVER`, `X509PATH_INTERMEDIATES` (colon- or whitespace-separated),
`X509PATH_AT`, `X509PATH_DNS_NAME`, `X509PATH_IP_ADDRESS` (takes precedence
over `X509PATH_DNS_NAME` when set), `X509PATH_JSON`, `X509PATH_EXTRA_ARGS`.

## Repository layout

```
src/x509path/
  certwrap.py    parsing, DER digests, single-edge P-256 ECDSA verification
  dnsnames.py    ASCII DNS parsing + RFC 5280 subtree matching/intersection
  generalnames.py mixed dNSName/iPAddress SAN + per-name-form constraints
  ipvalidate.py  IP-mode chain validation (all candidates, deterministic)
  rules.py       per-certificate profile/extension rules
  validate.py    signature-bound chain enumeration, cycle guard, RFC 5280
                 top-down validation, deterministic display path, reporting
  cli.py         command line
scripts/generate_sample_pki.py
compose.yaml, Dockerfile, compose/entrypoint.sh
tests/           PKI factory + 116 tests
```

## Running the tests

```sh
python3 -m pip install -e . pytest
python3 -m pytest
```

The suite generates same-name/different-key CAs, first-bad-then-good
cross-signed chains, nested permitted/excluded domain restrictions, self-issued
key-rollover and certificate-ring graphs, and asserts the trust conclusion and
display path are invariant over all input permutations.


## IP 地址服务器验证
新增互斥的 --ip-address / --dns-name。IP 模式接受 IPv4/IPv6 字面量（不含端口、括号、区域 ID 或子网），按地址内容匹配 IP SAN；DNS SAN 不能替代 IP SAN。该模式允许 DNS 与 IP SAN/NameConstraints 混合，逐类型处理约束：同一 CA 的同类型允许项是备选，不同 CA 的允许范围共同约束，排除项优先，未出现的名称类型不受其他类型允许项限制。IPv4 与 IPv6 不互相转换，所有下级 SAN 均受已有约束；self-issued 非末端换钥证书不受前序名称约束，但它的约束仍影响后代。保留真实签名建链、有效期、KU、EKU、pathLen、critical 扩展及固定 DER 锚校验。锚自身字段沿用原范围，不参与下级名称限制。所有候选路径各自判定，存在合法路径则按 DER 摘要序列择优，失败路径给出首个拒绝节点；JSON 标注 name_kind=ip 和规范 ip_address，DNS 模式原行为不变。名称及 IP 网络限制以 RFC 5280 为依据。
