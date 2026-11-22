# Secure Stellar Cyber 7.0 custom TI + Suricata QA plan (2026-11-22)

This is a QA-only engineering implementation. It is not a live customer TIP feed, Sensor installation, or public release.

## Existing vs custom coverage

Stellar's documented built-in feeds include Proofpoint/ET Pro IP, Domain, Rules; AlienVault OTX; DHS; PhishTank; OpenPhish; abuse.ch URLhaus and SSL certificates; and Stellar research. Customer tenant feed inventory is authoritative. Do not merely rebundle these sources as new custom TI.

The publicly published 383 v1.2 Suricata rules are preserved byte-for-byte. Of the 94 upstream ThreatDefence behavior signatures, 43 were already integrated and SID-remapped. Fifteen distinct additional signatures have been staged in a separate 398-rule QA candidate. Thirty-six remain deferred with per-rule reasons in validation/agentic-20261122/deferred-36-rule-review.csv. All 152 upstream IP-only network signatures are handled as TI candidates or hunting context, not auto-promoted Suricata alerts.

## OSINT source and rights matrix

| Source | Freshness / uniqueness | Rights / risk | Disposition |
|---|---|---|---|
| ThreatDefence Agentic | Repo updated 2026-11-21; unique agentic frameworks | Repository MIT; respect underlying research attributions | Active QA source, high-specificity IOC only |
| Cisco Talos ARTEX IP | 2546 IPv4 snapshot dated 2026-11-13, no per-IP last-seen | GitHub IOC repository CC0; snapshot is not live proof | HUNT ONLY, no block |
| InfobloxOpen TI | Campaign-specific domain/IOC research, repo updated 2026-10-30 | CC BY 4.0 with attribution | Next candidate adapter, confirm per-record recency |
| CERT Polska warning list | 24x7 active phishing domains, published frequently; recommend 5-minute retrieval; per-record add/remove timestamps | Explicitly permits commercial use, cannot imply CERT endorsement | Standalone **recent 24h / 5000-max QA** adapter, verify customer OEM overlap before live TIP |
| CISA KEV | Updated on official catalog changes | CC0; CVE not a native TSV IOC | Vulnerability and detection priority context |
| MISP warninglists | Updated policy lists of benign/shared infrastructure | CC0 with documented source exceptions | False-positive exclusion context |
| MISP 108-feed catalog | Mix of live, offline and restricted sources | Each feed has independent terms; catalog not license | Discovery only |
| ThreatFox | API recent indicators, automatic six-month expiry | API key, for-profit or commercial use may require paid entitlement | Disabled pending OEM rights |
| MalwareBazaar | New malware hashes and file intelligence | API key; commercial entitlement may be required | Disabled pending OEM rights |
| URLhaus | Frequent malicious URL indicators | Already in Stellar built-ins, commercial conditions | Skip rebundling |
| drb-ra/C2IntelFeeds | C2 verified 7/30/90-day windows | CC BY-NC-SA 4.0; noncommercial restriction | Excluded from OEM output |
| Maltrail Trails, latest corpus | Frequent trail changes, huge volume | 2026 license restricts OEM/MSSP redistribution | Excluded without permission |
| mhearsh/threat-intel-feed | Updates approx. every 2h | Wrapper CC BY but downstream Spamhaus/OpenPhish/C2IntelFeeds conditions still apply | Excluded without individual upstream permissions |
| Spamhaus DROP | Changed daily; IP lifecycle sensitive | Commercial use licensed | Excluded |
| blocklist.de | Recent 48-hour attacker IPs, updated every 30 minutes | Redistribution rights not established, noisy scanner source | Research only |
| Threatview | Published bulk IP/hash/URL feeds | License and quality need verification | Disabled |
| Tor/VPN/residential proxy | Frequent changes | Presence is not necessarily malicious | Context only |
| OpenPhish/PhishTank/AlienVault/ET Pro | Active feeds | Already in Stellar, possible Proofpoint OEM coverage | Exclude duplication |

References:
- https://docs.stellarcyber.ai/prod-docs/7.0.x/Configure/Threat-Intelligence-Platform-About.htm
- https://docs.stellarcyber.ai/7.0.xs/Configure/Threat-Intelligence-Platform-Feeds.htm
- https://www.misp-project.org/feeds/
- https://github.com/ThreatDefence/agentic-attack-detections
- https://github.com/Cisco-Talos/IOCs/blob/main/2026/11/artex-and-beyond.txt
- https://github.com/infobloxopen/threat-intelligence
- https://cert.pl/en/warning-list/
- https://github.com/CERT-Polska/warning-list-tools
- https://github.com/MISP/misp-warninglists
- https://github.com/drb-ra/C2IntelFeeds
- https://github.com/stamparm/trails
- https://github.com/mhearsh/threat-intel-feed
- https://threatfox.abuse.ch/api/
- https://bazaar.abuse.ch/api/
- https://www.spamhaus.org/faqs/commercial-data/

MISP catalog inclusion or an "active" badge does NOT prove actual feed availability or redistribute rights.

## Stellar native ingestion

Custom TIP uses TAXII 2.1 or TSV with no header: four TAB-separated values TYPE, VALUE, SOURCE and SCORE.

Type must be one of ip, domain, url, md5-hash, sha1-hash, sha256-hash; SOURCE must contain only alphanumeric, underscore and dash; SCORE is integer 0-100. Documented TSV IP is IPv4. See customer release notes before assuming IPv6 support.

The documentation specifies a maximum of 30 Custom feeds per organization, TSV below 100MB, completion within 30 seconds, ingestion of up to 25000 IOC per day, and customer-selected hourly polling. The custom feed feature may be restricted until Stellar support assesses resources. Testing the real DP Feed list is mandatory.

## Secure supply chain

1. In GitHub Actions, fetch only the two explicitly allowlisted HTTPS upstream URLs with normal CA/hostname verification. Reject HTTP redirects, empty/oversized sources and bad CSV schema. The six-hour scheduled task *only creates a QA artifact*. Nothing is automatically released to customers.
2. tools/agentic_osint_feed.py normalizes, screens out benign AI APIs, stale IPs, malformed values, favicon/logo fingerprints, and creates agentic-malicious-DRAFT.tsv, agentic-ip-HUNT-ONLY.csv, source audit CSV and SHA256/expiry manifest.
3. CERT Polska is handled by a separate QA adapter (tools/cert_polska_osint.py): it filters active phishing domains first added within 24 hours, rejects more than 5000 records, and does **not** claim these are unrepresented in the customer's existing Proofpoint data. The CERT staging file is not included in the primary signed manifest, so it must not be published without a separate verified promotion path.
4. Authorized promotion must review source changes, licensing, unexpected spikes and false positives, and change the manifest status to APPROVED_FOR_DEPLOYMENT. Keep signing private keys separate from the public repository, web host and collector. Sign the final manifest using Ed25519 (tools/verify_ti_release.py sign).
5. The trusted serving origin must verify signature, every SHA256, expiration, row schema and a persistently stored monotonic sequence (tools/verify_ti_release.py verify --require-approved). Promote all signed objects atomically, retain last-known-good only until it expires, and fail closed with an alert on failed signature or expired snapshot.
6. Serve just the approved TSV through a customer-accessible HTTPS endpoint with verified certificate/hostname, TLS 1.2/1.3, dedicated Basic Auth, restricted GET-only path, no HTTP redirect fallback and no public GitHub Raw URL as the production feed. Rotate credentials, monitor errors, staleness, feed size and TIP last-ingestion time.
7. On a nonproduction Stellar DP, add a Custom TSV Feed with URL, Basic auth, polling and retention. Verify collected IOC count, metadata, matching events and expiry. Plan TAXII 2.1 if richer first/last-seen, valid-until and confidence semantics justify a service.
8. Back up Sensor custom_defined.rules before importing a full file: the Import Security Rules operation replaces that file. Independently test 398-rule QA with Suricata -T, synthetic positive/negative PCAP, Sensor EVE, DP Alert/Case and operational false positives.
9. No automated blocking without independent corroboration. Historical Talos IPs, unverified bulk data, commercial-license-restricted sources, and agent model endpoints remain hunting/context.

### Illustrative Nginx HTTPS gateway only (NOT deployed)

    server {
        listen 443 ssl;
        server_name ti.example.invalid;
        ssl_certificate /etc/ssl/stellar-ti/fullchain.pem;
        ssl_certificate_key /etc/ssl/stellar-ti/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        location = /feeds/agentic.tsv {
            auth_basic "Stellar-TIP";
            auth_basic_user_file /etc/nginx/stellar-tip.htpasswd;
            alias /srv/stellar-ti/approved/agentic-malicious-DRAFT.tsv;
            default_type text/tab-separated-values;
            add_header Cache-Control "no-store" always;
            limit_except GET { deny all; }
        }
    }

The trusted origin may expose only *verified and approved* files. TLS protects TSV in transit, but **neither TSV nor TAXII implies that Stellar checks our detached Ed25519 signature**. The signature is a controlled publishing-origin gate, not a claimed native Stellar client feature. Independently validate certificate verification and Basic Auth in the customer tenant.

### Local QA

    python3 validation/agentic-20261122/run_offline.py --static-only
    python3 -m unittest discover -s validation/agentic-20261122 -p 'test_*.py' -v
    python3 validation/agentic-20261122/run_offline.py
    python3 tools/agentic_osint_feed.py --allow-network --output /tmp/stellar-agentic-ti-staging

Signing commands are available in tools/verify_ti_release.py; do not store signing keys in GitHub or sign a DRAFT as if it were released.

## Deployment blockers (separate from development)

- [ ] Exact-HEAD 398-rule Suricata 7/8 CI and TI signature tests green.
- [ ] Commercial/OEM data-rights check for any additional external source.
- [ ] Trusted HTTPS+Basic gateway, protected Ed25519 signing key and monotonic release state.
- [ ] Actual Stellar TIP Custom Feed enabled, exact OEM overlap measured and E2E confirmed.
- [ ] Real Sensor + DP Alert/Case tests and benign-site false-positive sampling.
- [ ] Owner release approval before public deployment or production import.
