# Strict freshness-first Stellar Cyber OSINT assessment — 2026-11-22

## Decision: quality and expiry are the product, not IOC volume

The legacy Proofpoint/ET Pro/OTX/URLhaus/OpenPhish/PhishTank data are already documented built-ins of Stellar Cyber 7.0. Custom feed value is **additional independent recent behavioral evidence** (not a rebranded bulk blacklist).

Of the surveyed source classes, only **two** are admitted into the stricter QA stage:

1. **CERT Polska** (active phishing/fraud domains, official commercial reuse policy, added/removed timestamps, recommended 5-minute refresh). Export only active records first added within 24 hours; maximum 750; exact domain matches. Existing 2026-11-22 QA sampled 126,662 total records and 449 newly active records.
2. **OffSeq Mirage** (honeypot TCP handshake and application data, last-seen, confidence, sensors/networks, fraud/shell/ransom tags, candidate exclusion lists; daily publication with 24h holding period). Its *data* are CC BY 4.0, code MIT; attribution required. Use only last-seen within 24h, confidence >=85, >=3 sensors and >=2 networks, and one of shell-commands/db-ransom/mirai-like/sip-fraud. Remove Tor, VPN, CGNAT and research-scanner addresses. Volume cap 200. Snapshot SHA256 and licensing schema must match source manifest. At 2026-11-22 06:00 UTC the public 7-day CSV had 1,737 records, but **9** met the strict 24h/85/strong-tag predicate. These are *recent observed hostile source IPs, not confirmed C2 servers*.

Operational QA uses independent TSVs to preserve semantics: strict-recent-phishing-DRAFT.tsv (CERTPolska) and strict-recent-attackers-DRAFT.tsv (OffSeqMirage). Neither is published to a customer, and real tenant OEM overlap is still unmeasured.

## Independent sources screened (license, freshness, confidence, overlap)

| Feed | Freshness / verification observed | Accuracy / commercial constraint | Verdict |
|---|---|---|---|
| CERT Polska Warning List | 24x7 maintained, vendor says update every 5 min; add/removal timestamps | Official active fraud/phishing list, commercial use explicitly permitted | **STRICT ACTIVE** (domain, 24h admission, active now) |
| OffSeq Mirage | Data branch and feed.json timestamp on 2026-11-22, CSV last_seen per IP, once daily | TCP handshake, >=3 sensor/>=2 network publisher gate, CC BY 4.0 data | **STRICT ACTIVE** (IP, >=85, high-risk tags, <24h last_seen) |
| emth361h/honeypot-iocs | Metadata updated 2026-11-22, first/last_seen day granularity | One claimed self-hosted honeypot; MIT but no public raw independent evidence; research-scanner removal important | **CORROBORATION ONLY**, do not import all 4,522 high IPs |
| neilweitzel/xfeeds clean | Continuous source aggregation; 2026-11-21 recent commit | Explicit licensed provenance tier, dependent sources, mostly scanners/brute force, no independent badness proof | **CORROBORATION ONLY**, not standalone malicious IPs |
| IPsum | Daily refreshed aggregate, Unlicense | Counts upstream list overlaps, not independent sensors or event timestamps | **EXCLUDE**, no new threat-specific evidence |
| InfobloxOpen campaign IOC | Latest code/main 2026-10-30 | CC BY 4.0, but episodic campaigns, not continuous current live indicators | **CAMPAIGN RESEARCH ONLY** |
| ThreatDefence Agentic IOC | Repo updated 2026-11-21, 514 records | Report date is NOT last observed time; high confidence includes framework favicon and benign update services | **HISTORICAL/HUNT**, not strict-live even for the earlier 54 draft |
| Cisco Talos ARTEX IOC | 2,546 IPs static snapshot committed 2026-11-13 | CC0, no per-IP last_seen, IP reassignment possible | **HISTORICAL/HUNT**, never auto-export as live malicious |
| cisspco Cobalt Strike Tracker | Daily updated 2026-11-22, 6 attributed IPs | Only malware/campaign attributed "block-safe" indicators, but no per-IP live observation time in published simple IP file | **RESEARCH/HUNT**, could add once fresh observed evidence is attached |
| ThreatFox | Frequent live C2 IOC submissions; six-month aging | API Auth-Key required; for-profit/OEM use may need paid license; some overlap | **LICENSE-PENDING**, exclude |
| MalwareBazaar | Frequent malware hash analysis | API key and commercial service terms, OEM rights unverified | **LICENSE-PENDING**, exclude |
| URLhaus | Frequent malware URL data | Already listed in Stellar built-ins; duplication and rights concerns | **BUILT-IN EXCLUDE** |
| OpenPhish | Continuous phishing feed | Stellar built-in | **BUILT-IN EXCLUDE** |
| PhishTank | Phishing reporting | Stellar built-in | **BUILT-IN EXCLUDE** |
| AlienVault OTX | Community IOC pulses | Stellar built-in, source references may be circular | **BUILT-IN EXCLUDE** |
| Proofpoint ET Pro IP/domain/rules | OEM licensed and near-real time | Current Stellar native feed; avoid rebranding | **BUILT-IN EXCLUDE** |
| CISA KEV | Updated with known exploited vulnerabilities | Excellent vulnerability priority context, but CVE not a supported malicious IP/domain/hash TSV | **CONTEXT, NOT TIP IOC** |
| FIRST EPSS | Daily probabilistic CVE exploitation forecast | Not an IOC or malicious reputation, not the same as observed exploit | **CONTEXT, NOT TIP IOC** |
| MISP Warninglists | Periodic legitimate/shared infrastructure lists | Positive filtering/correlation, not attack lists | **FALSE POSITIVE GUARD** |
| Shadowserver reports | Daily verified 24h/7d reports for registered ASN/constituency | No unrestricted global IP feed and dashboard is not resellable | **CUSTOMER-LOCAL RESEARCH**, not OEM redistributable |
| URLScan.io | Frequent crawled URLs | Screenshot URL presence not sufficient for confirmed malicious, API terms / privacy | **NOT AN AUTOMATIC MALICIOUS FEED** |
| blocklist.de | Often 30min refreshed attack logs | Predominantly scanners/brute force, IP churn, commercial redistribution not established | **EXCLUDE** |
| ThreatMon daily C2 repository | Advertises daily | Last repository push observed 2023-12-27, stale | **EXCLUDE STALE** |
| FFraud IP database | Advertises 30-minute update, massive count | Repo pushed 2026-11-03, not near-real-time at 2026-11-22 | **EXCLUDE STALE/UNVERIFIED** |
| C2IntelFeeds drb-ra | Verified 7/30/90d C2 scans | CC BY-NC-SA 4.0 noncommercial | **EXCLUDE OEM** |
| Spamhaus DROP | Maintained frequently | Commercial feed license required | **EXCLUDE UNTIL LICENSED** |
| IP-DB/FireHOL/Threatkill aggregators | Mostly daily scraped bulk IPs | Mixed licensing, duplicate sources, no per-IP live truth | **EXCLUDE** |
| Tor/VPN/residential proxy lists | Near-live IP lists | Legitimate privacy infrastructure, not maliciousness proof | **CONTEXT ONLY** |
| CTI.FYI | Recent ransomware data | Noncommercial without paid product rights | **EXCLUDE UNTIL LICENSED** |

**Sources**:
- https://docs.stellarcyber.ai/prod-docs/7.0.x/Configure/Threat-Intelligence-Platform-About.htm
- https://docs.stellarcyber.ai/7.0.xs/Configure/Threat-Intelligence-Platform-Feeds.htm
- https://cert.pl/en/warning-list/
- https://github.com/offseq/mirage-feed (README and LICENSE-DATA)
- https://github.com/emth361h/honeypot-iocs
- https://github.com/neilweitzel/xfeeds
- https://github.com/stamparm/ipsum
- https://github.com/infobloxopen/threat-intelligence
- https://github.com/ThreatDefence/agentic-attack-detections
- https://github.com/Cisco-Talos/IOCs
- https://github.com/cisspco/Cobalt-Strike-Tracker
- https://threatfox.abuse.ch/api/
- https://www.shadowserver.org/faq/what-information-do-you-include-in-your-reports/
- https://github.com/ThreatMon/ThreatMon-Daily-C2-Feeds
- https://github.com/FFraud-com/ip-fraud-database
- https://github.com/drb-ra/C2IntelFeeds
- https://cti.fyi/

**Freshness is evaluated from the last *malicious observation*, NOT the feed download, GitHub push or report publication date.** A source updated every minute with yesterday's unverified IPs is not a fresh threat feed.

## Source admission and removal gates

- Start only when metadata explicitly identifies current active/last_seen observations.
- Every feed must be licensed for the intended use including downstream provision to Stellar customers. Source availability is not a redistribution license.
- Deliberate full-source filtering: no general-purpose scanner IPs, CDN or shared infrastructure, simple User-Agent strings, anonymous VPN/Tor, framework favicon, or leaked static historical lists.
- OffSeq must have source-generated age <48h, record last_seen <24h, confidence >=85, verified source SHA, concrete high-risk attack tag and multi-sensor independence.
- CERT Polska domains must currently be present, deleted_at empty, and created <24h. The source itself advises deleting domains immediately when removed.
- Read-only hourly QA source retrieval; no auto publication, no merge and no customer import. GitHub Actions scheduling can be delayed. Stellar 7.0 native custom feed polls at hour granularity. Feed age alert threshold should be <2 hours for CERT and <48 hours for OffSeq daily publisher.
- Strict-live manifest includes per-file SHA256, source hashes, data rights, expiry, sequential ID; signing under an authorized offline Ed25519 key is mandatory before host-side release. User-facing Stellar API is TLS with dedicated Basic Auth; the host must verify signature, not depend on Stellar native signature-checking.
- On source outage, do not append stale data. Serve last-known-good only during its signed expiration window, then reject refresh and alert.
- **Removal semantics are an unresolved Stellar TIP validation gate**: disappearing from an HTTP TSV snapshot may not delete an existing IOC immediately. Verify tenant Retention Period and removal on repeated refresh, not just ingestion. A stale IOC staying in the platform defeats freshness.
- Never confuse source confidence with measured detector precision. Before production, adjudicate matches from benign enterprise traffic, measure FP, and compare with actual Proofpoint/ET sources. Do not use inferred overlap to make "unique" claims.
- Publish source confidence, observation window, capture timestamp, license and removal policy next to every allowed feed. The fixed four-column Stellar TSV cannot carry last_seen, so preserve signed sidecar metadata and support a TAXII 2.1 path if explicit per-IOC expiry is required.

## Acceptance checklist

- [x] Two independent, commercially eligible, recent-data candidate providers identified
- [x] OffSeq public CSV, exclusion list and signed-by-provider checksum manifest metadata inspected
- [x] Strict current-data only generator and synthetic policy regression tests added in Draft PR #60
- [x] Legacy 383+15 = 398 Suricata QA candidate remains unchanged
- [ ] New strict staging exact-HEAD CI green on real HTTPS downloads
- [ ] Real Proofpoint OEM content-level overlap measured in customer DP
- [ ] Trusted origin / out-of-band Ed25519 signing / monotonic release history configured
- [ ] Customer DP TIP time-to-ingest and IOC deletion TTL tested, and Sensor Alert/Case E2E verified
- [ ] Owner release approval before main merge/public data or production feed use

The source selection is an engineering policy, **not a claim of independently established threat-ground-truth precision**.
