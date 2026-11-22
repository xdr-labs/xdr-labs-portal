# Stellar Cyber Custom TIP: exactly one public feed (2026-11-22)

## Owner decision

**No customer IDs, tenant accounts, credential issue/rotation, or separate IP and
phishing URLs.** Every Stellar Cyber customer subscribes to the *same* current
four-column TSV at one HTTPS URL:

\`https://ti.example.invalid/stellar-ti.tsv\`

The hostname is deliberately invalid until an authorized operator supplies an
approved domain/TLS cert and deploys the service. This is **NOT LIVE**.

Stellar Cyber TIP Custom TSV configuration: one feed URL, no Basic credentials,
refresh every available poll interval. One line per IOC, no header:

\`\`\`tsv
ip	203.0.113.9	OffSeqMirage	90
domain	phishing.example.invalid	CERTPolska	75
\`\`\`

The addresses above are **documentation-only**; they are not current malicious
indicators and must not be added to any live feed.

## Supply-chain and end-to-end path

1. Scheduled QA collectors fetch licensed original inputs from CERT Polska,
   OffSeq Mirage and Jacobrakai. The 41-source catalog includes more research
   candidates but **none are enabled without rights/freshness/false-positive gates**.
2. Origin checks validate OffSeq's publisher Minisign signature, immutable
   source SHA256SUMS and freshness, and check each source's individual IOC
   current observation timestamp and quality.
3. The verification engine computes IP/domain staging TSVs *separately inside
   the trusted package only*, retaining source-specific CSV evidence, exact
   original bytes and license attribution.
4. Before any authorized release, the independent builder reconstructs all
   emitted IOCs byte-for-byte from frozen inputs, rejects tampering, and
   requires a protected out-of-band Ed25519 local signature. No signing key
   is stored in GitHub, the feed service or repo.
5. The release is atomically promoted only after approval. The loopback
   reader checks the source publisher signature, local Ed25519 signature,
   anti-rollback sequence, current 24-hour IOC evidence and license on GET.
6. The reader combines the signed IP and domain TSV files from **one
   validated release** into one HTTP response. No mixed versions and no
   unsigned combined-file cache. Other feed types (URL, SHA256) can be added
   after they are independently licensed/validated and included in the same
   signed release.
7. Nginx terminates public TLS, rate-limits clients, exposes only the one
   \`/stellar-ti.tsv\` endpoint and forwards to \`127.0.0.1:18332\`.
   No HTTP fallback; \`/internal/healthz\` is loopback-only and blocked
   from the public proxy. No Basic authentication and no customer DB.

When a signature, source, observation or release expires, HTTP returns **503**,
not an outdated feed. Whether Stellar retains stale previously imported
indicators is a *separate real DP validation gate*. The service cannot delete
Stellar's existing imported indicators without customer DP testing.

## Code and operations

- Public loopback read-only service: \`tools/ti_public_service.py\`
- Restricted signed origin/release: \`tools/strict_ti_gateway.py\`
- Publisher-signed inputs and bytes: \`tools/verify_offseq_origin.py\`
- Source-to-IOC replay: \`tools/verify_ti_build_replay.py\`
- Public TLS only, ONE endpoint: \`deploy/stellar-ti/nginx-single-feed.conf.example\`
- Restricted process service example: \`deploy/stellar-ti/stellar-ti-public.service.example\`
- Isolated integration tests: \`validation/agentic-20261122/test_ti_public_service.py\`

Customer configuration in Stellar Cyber 7.0 (after approved deployment):
TIP → Custom Feed → TSV → URL = \`https://<approved-host>/stellar-ti.tsv\`,
authentication = none, refresh as supported. Confirm license attribution
and actual Proofpoint/ET OEM overlap separately.

## Acceptance and release gates

- [x] Single uniform response, Stellar four-column TSV for mixed IOC types
- [x] No tenant ID, no customer account, no Basic Auth, no alternate split URLs
- [x] Signed release freshness, source proof, mismatch and tampering fail closed
- [x] Loopback-only HTTP testing with synthetic IOCs, repeatable in CI
- [ ] Approved public hostname and TLS certificate; external server deployment
- [ ] Authorized out-of-band signer and audited release/promotion pipeline
- [ ] Actual customer Stellar TIP imports, refresh latency, deletion/expiry,
      true OEM novelty and EVE→Alert/Case E2E
- [ ] Explicit publication/release approval

No production endpoint was created or exposed by these examples. A CI staging
artifact is QA-only, not an authenticated approved release.
