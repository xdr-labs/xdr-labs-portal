# Stellar Cyber strict TI: verified-source staging and signed HTTPS gateway runbook
Date: 2026-11-22. **Draft PR #60 only; no live endpoint has been created.**

## What can and cannot be claimed

- The published v1.2 rule set (383) is unchanged. A **398-rule candidate** (15 additive agentic signatures) remains QA-only.
- Verified-source QA runs every hour **after merge to main**, not while the workflow resides only in a Draft PR.
- OffSeq Mirage source integrity: pinned public Minisign key verifies detached signature on SHA256SUMS. The signed comment checks publish time/build; the selected feed.json, attack CSV, scanner and anonymizer files must match SHA256SUMS before use. This was demonstrated in GitHub CI.
- CERT Polska: official commercial-use-compatible active phishing domains, added within 24h and not removed. HTTPS and schema/clock checks; no independent upstream publisher signature currently exposed by this adapter.
- Jacobrakai: original Cowrie/Heralding sensor and CC0 data, hourly JSON/CSV consistency and last_seen checks. **Uncorroborated credential-only addresses are HUNT-ONLY**, even if ban totals are high. Only loader-tier or an address independently corroborated by a qualifying OffSeq sensor record may enter the imported IP feed.
- **No observed-zero-false-positives claim.** The selected IP source is evidence of hostile activity against honeypots, not proof of C2, not proof that every future connection from that IP is malicious.
- Without the actual Stellar TIP active feed inventory and exported Proofpoint/ET indicators, uniqueness against OEM content is **NOT MEASURED**.

## QA output layout

The strict stage produces the following:
- strict-recent-attackers-DRAFT.tsv (IP with OffSeqMirage/JacobHoneypot/Corroborated labels)
- strict-recent-phishing-DRAFT.tsv (domain with CERTPolska)
- strict-ip-evidence.csv (source, first_seen, last_seen, sensor counts and attack tags/tier)
- strict-domain-evidence.csv (domain added_at and empty removed_at)
- strict-manifest.json (SHA256 of all four signed artifacts, source SHA256, source dates, sequence, expiry)
- jacob-credential-HUNT-ONLY.csv (not in TIP import or signed release inventory)
- origin-verification.json (hash-bound upstream origin-verification receipt, **part of the locally signed release manifest**)
- offseq-SHA256SUMS and offseq-SHA256SUMS.minisig (the exact upstream publisher signature/checksums, **part of the locally signed release**)
- upstream-rule-drift.json and optional other source health status (research only)

Only the two TSV files are presented to Stellar TIP. The two evidence CSVs **and all three source-origin proof files** are part of the protected signed release inventory, re-validated at promotion and on every gateway GET. Research/hunting outputs are never served as TIP feeds.

## No insecure direct distribution

Stellar Cyber's custom TIP collector supports an HTTPS TSV endpoint and Basic Auth. TSV is a serialization format, not encryption or signature transport. Customer access must be over TLS with CA/hostname checking, dedicated short-scope Basic credentials and no insecure HTTP fallback.

A file checksum alone does not authenticate its source; a checksum delivered alongside a substituted TSV can be altered too. OffSeq upstream Minisign authenticity is independently pinned. The *local* release manifest is signed using a separate, out-of-repo Ed25519 private key.

Stellar Cyber **does not document client-side verification of this detached signature**. Therefore trusted origin must validate release, expiry, source records and per-file hashes before answering requests. Do not serve the raw unsigned QA artifacts from GitHub Pages.

## Promotion procedure (only after operator authorization and test-tenant E2E)

1. Verify exact-head GitHub QA and source attestation. Download CI artifacts from a trusted workflow. The staged release includes the publisher-signed OffSeq SHA256SUMS, its Minisign signature and the verification receipt, all individually SHA256-bound in the **locally Ed25519-signed manifest**. The gateway independently verifies the pinned publisher key and original upstream digests at promotion and every GET; it does **not** trust only the JSON receipt. CERT Polska and Jacobrakai remain HTTPS-only sources (not upstream publisher-signed).
2. Independently corroborate license, source and false-positive policy. Adjudicate a customer clean-traffic sample, and check native Proofpoint/ET feed overlap via the read-only tool:
   python3 tools/audit_stellar_ti_overlap.py --current /path/strict-recent-attackers-DRAFT.tsv /path/strict-recent-phishing-DRAFT.tsv --oem-csv /path/tenant-active-iocs.csv --oem-generated-at 2026-11-22T06:00:00+00:00 --output /tmp/ti-overlap.json
3. In an operator-controlled staging directory, copy the four signed-eligible files and strict-manifest.json. Explicitly change status to APPROVED_FOR_DEPLOYMENT only after security review; never sign an original DRAFT for production.
4. Sign the final manifest *off the collection runner and web host*, using a protected Ed25519 key, and write strict-manifest.sig. The private key may not be committed, uploaded to GitHub Actions artifacts, installed on the HTTP gateway, or logged.
5. Audit before mutation. Minisign must be installed at the trusted validation origin; source proof is independently re-verified with pinned public key:
   python3 tools/strict_ti_gateway.py audit --stage /secure/staged --origin /srv/stellar-ti --public-key /secure/trusted-publisher.pub
6. In a nonproduction simulation, the --apply form atomically copies and verifies the signed files into releases/<sequence>, stores last_sequence and switches current. It rejects non-increasing sequences, missing signer approval, tampered files, out-of-window observations, uncorroborated credential-only IPs, malformed or missing evidence. Test this process before enabling any actual consumer:
   python3 tools/strict_ti_gateway.py promote --stage /secure/staged --origin /tmp/stellar-ti-test-origin --public-key /secure/trusted-publisher.pub --apply
7. The optional QA gateway reads the current signed release **on every GET** and returns 503 when signatures, current retention state, signed evidence or timestamps fail. It binds to 127.0.0.1 only:
   python3 tools/strict_ti_gateway.py serve-loopback --origin /tmp/stellar-ti-test-origin --public-key /secure/trusted-publisher.pub --port 18331

Do not use port 18331 on a public interface. It has no built-in TLS or Basic Auth; those are termination-layer responsibilities. Production authentication/permission changes and deployment require separate owner approval.

### Example Nginx TLS+Basic frontend (design only, NOT installed)

    server {
        listen 443 ssl;
        server_name ti.example.invalid;
        ssl_certificate /etc/ssl/stellar-ti/fullchain.pem;
        ssl_certificate_key /etc/ssl/stellar-ti/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        auth_basic "Stellar Cyber TIP";
        auth_basic_user_file /etc/nginx/stellar-ti.htpasswd;
        location = /feeds/recent-attackers.tsv {
            proxy_pass http://127.0.0.1:18331/feeds/recent-attackers.tsv;
            proxy_cache off;
            proxy_set_header Host $host;
            add_header Cache-Control "no-store" always;
            limit_except GET { deny all; }
        }
        location = /feeds/recent-phishing.tsv {
            proxy_pass http://127.0.0.1:18331/feeds/recent-phishing.tsv;
            proxy_cache off;
            proxy_set_header Host $host;
            add_header Cache-Control "no-store" always;
            limit_except GET { deny all; }
        }
    }

Use tenant-specific secrets, access controls, audit logs, rate limits and dedicated origin process permissions before any production operation. Certificates must be publicly trusted by the Stellar DP or explicitly CA-trusted according to its documented connector behavior.

## Freshness vs Stellar IOC retention

An updated HTTPS file might exclude an IP that was seen yesterday. **That does not prove the customer DP removed the previous IOC.** On a test tenant, deliberately insert and remove a synthetic indicator, cause two refreshes, then inspect the TIP's actual current indicator table and Retention Period. Do not claim a fresh customer-visible feed until last-seen based expiry is confirmed downstream.

Test cases:
- IP from the prior feed disappears on the next generation;
- domain removed from the active CERT Polska feed disappears within customer-agreed TTL;
- vendor source unavailable does not lead to serving an expired signed snapshot;
- source and release signatures altered → origin refuses to serve;
- replay of older release sequence → 403/503 and alert;
- alerts and Cases caused only by corroborated malicious activity, not a bare User-Agent or historical IP;
- certificate expiry, HTTP error, Basic auth failure, volume spikes and source change all produce observable telemetry.

**Current state:** all code/CI is a controlled engineering candidate. Production, customer data import, signed publishing keys, real TLS gateway, Proofpoint duplicate export, DP deletion behavior and Modular Sensor Alert/Case E2E are not verified.
